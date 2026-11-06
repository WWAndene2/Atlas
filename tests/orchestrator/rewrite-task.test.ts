import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { binaryId, functionId, loadAnalysis } from "../../src/orchestrator/load-binary.js";
import { proposeRewrite } from "../../src/orchestrator/propose-rewrite.js";
import { rewriteQueue } from "../../src/orchestrator/rewrite-queue.js";
import { prototypeOf, rewriteTask } from "../../src/orchestrator/rewrite-task.js";
import { verifyRewrite } from "../../src/verify/recompile/verify-rewrite.js";
import { compiledBytes, compiledRun } from "../verify/recompile/compile-helper.js";

// g is called by f; both compiled from one unit so their code is contiguous, as in a real binary.
const source = [
  "__attribute__((noinline)) int g(int x) { return x * 3 + 1; }",
  "int f(int x) { return g(x) + g(x + 1); }",
  "",
].join("\n");
const [gBytes, fBytes] = compiledRun(source, ["g", "f"]) as [Uint8Array, Uint8Array];
const sha256 = "7".repeat(64);
const gAddress = "0x1000";
const fAddress = `0x${(0x1000 + gBytes.length).toString(16)}`;
const g = functionId(sha256, gAddress);
const f = functionId(sha256, fAddress);
const toolchain = { cc: "gcc", flags: ["-O2"] };

let store: GraphStore;
beforeEach(() => {
  store = new GraphStore(":memory:");
  loadAnalysis(
    store,
    "target",
    {
      tool: { name: "test", version: "1" },
      sha256,
      functions: [
        {
          address: gAddress,
          size: compiledBytes(source, "g").length, // its code, without the padding up to f
          label: "FUN_g",
          thunk: false,
          code: Buffer.from(gBytes).toString("hex"),
        },
        { address: fAddress, size: 4, label: "FUN_f", thunk: false, code: Buffer.from(fBytes).toString("hex") },
      ],
      calls: [{ from: fAddress, to: gAddress }],
      strings: [],
      limitations: [],
    },
    undefined,
    "x86_64",
  );
  store.proposeHypothesis({
    schema_version: 1,
    id: `hyp_${"1".repeat(32)}`,
    node: binaryId(sha256),
    kind: "toolchain",
    value: { ...toolchain, verified: 1, sample: 1, ties: [], clues: [] },
    confidence: "inferred",
    evidence: [binaryId(sha256)],
    author: { agent: "toolchain-probe" },
  });
});
afterEach(() => store.close());

describe("rewriteQueue", () => {
  it("puts callees before callers and drops what a verified rewrite covers", async () => {
    expect(rewriteQueue(store, binaryId(sha256)).map((q) => q.id)).toEqual([g, f]);
    const h = proposeRewrite(store, g, { language: "c", source, name: "g" }, "agent");
    await verifyRewrite(store, h.id, toolchain);
    expect(rewriteQueue(store, binaryId(sha256)).map((q) => q.id)).toEqual([f]);
  });
});

describe("rewriteQueue and generated code", () => {
  it("leaves linker stubs and fragments out", () => {
    const store = new GraphStore(":memory:");
    const sha = "2".repeat(64);
    loadAnalysis(store, "t", {
      tool: { name: "test", version: "1" },
      sha256: sha,
      functions: [
        { address: "0x10", size: 4, label: "FUN_10", thunk: false, code: "90909090" },
        { address: "0x20", size: 4, label: "plt0", thunk: false, code: "90909090", generated: "linker" },
        { address: "0x30", size: 4, label: "caseD_9", thunk: false, code: "90909090", generated: "fragment" },
      ],
      calls: [],
      strings: [],
      limitations: [],
    });
    expect(rewriteQueue(store, binaryId(sha)).map((q) => q.label)).toEqual(["FUN_10"]);
    store.close();
  });
});

describe("rewriteTask", () => {
  it("gives the original instructions, the closest attempt compiled, and verified callee prototypes", async () => {
    const callee = proposeRewrite(store, g, { language: "c", source, name: "g" }, "agent");
    await verifyRewrite(store, callee.id, toolchain);
    const wrong = proposeRewrite(
      store,
      f,
      { language: "c", source: "int f(int x) { return x; }\n", name: "f" },
      "agent",
    );
    await verifyRewrite(store, wrong.id, toolchain);

    const task = await rewriteTask(store, store.getNode(f) as never);
    expect(task.status).toBe("open");
    expect(task.toolchain).toMatchObject(toolchain);
    expect(task.original[0]?.address).toBe(fAddress);
    expect(task.original.some((i) => i.text.startsWith("call"))).toBe(true);
    expect(task.closest?.hypothesis).toBe(wrong.id);
    expect(task.closest?.compiled.length).toBeGreaterThan(0);
    expect(task.callees).toEqual([
      expect.objectContaining({ id: g, prototype: "__attribute__((noinline)) int g(int x)" }),
    ]);
    expect(task.neighbours.previous?.id).toBe(g);
    expect(task.answer).toContain(`atlas propose rewrite ${f}`);
  });

  it("finds a function's declaration in its source", () => {
    // One line from the start of the definition: a return type on the line before is not part of it.
    expect(prototypeOf("static int h(char *s,\n  int n)\n{ return n; }", "h")).toBe("static int h(char *s, int n)");
    expect(prototypeOf("int h(int);", "h")).toBeUndefined();
  });
});
