import { describe, expect, it } from "vitest";
import { GraphStore } from "../../../src/graph/index.js";
import { functionId, loadAnalysis } from "../../../src/orchestrator/load-binary.js";
import { proposeRewrite } from "../../../src/orchestrator/propose-rewrite.js";
import { VerifyError, verifyRewrite } from "../../../src/verify/recompile/verify-rewrite.js";
import { compiledRun } from "./compile-helper.js";

// f tail-jumps to g, defined just before it in the same file: in the original the assembler resolves that jump
// itself (a short jump), so f cannot be reproduced alone, only together with g.
const source = [
  "static __attribute__((noinline)) int g(int x) { return x * 3 + 1; }",
  "int f(int x) { if (x > 5) return g(x - 1); return 7; }",
  "",
].join("\n");
const [gCode, fCode] = compiledRun(source, ["g", "f"]).map((b) => Buffer.from(b).toString("hex")) as [string, string];
const sha256 = "8".repeat(64);
const g = functionId(sha256, "0x1000");
const f = functionId(sha256, `0x${(0x1000 + gCode.length / 2).toString(16)}`);
const toolchain = { cc: "gcc", flags: ["-O2"] };

function graph(): GraphStore {
  const store = new GraphStore(":memory:");
  loadAnalysis(store, "target", {
    tool: { name: "test", version: "1" },
    sha256,
    functions: [
      { address: "0x1000", size: gCode.length / 2, label: "FUN_g", thunk: false, code: gCode },
      { address: `0x${(0x1000 + gCode.length / 2).toString(16)}`, size: 1, label: "FUN_f", thunk: false, code: fCode },
    ],
    calls: [],
    strings: [],
    limitations: [],
  });
  return store;
}

describe("verifying a run of neighbouring functions", () => {
  it("passes the run where the function alone cannot", async () => {
    const store = graph();
    const alone = proposeRewrite(store, f, { language: "c", source, name: "f" }, "agent");
    expect((await verifyRewrite(store, alone.id, toolchain)).check.result).toBe("fail");
    const run = proposeRewrite(store, g, { language: "c", source, name: "g", last: { node: f, name: "f" } }, "agent");
    const { hypothesis } = await verifyRewrite(store, run.id, toolchain);
    expect(hypothesis.confidence).toBe("verified");
    store.close();
  });

  it("refuses a run that goes backwards", async () => {
    const store = graph();
    const h = proposeRewrite(store, f, { language: "c", source, name: "f", last: { node: g, name: "g" } }, "agent");
    await expect(verifyRewrite(store, h.id, toolchain)).rejects.toThrow(VerifyError);
    store.close();
  });
});
