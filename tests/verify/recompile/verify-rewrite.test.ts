import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { GraphStore } from "../../../src/graph/index.js";
import { functionId, loadAnalysis } from "../../../src/orchestrator/load-binary.js";
import { proposeRewrite } from "../../../src/orchestrator/propose-rewrite.js";
import { verifyRewrite } from "../../../src/verify/recompile/verify-rewrite.js";
import { compiledBytes } from "./compile-helper.js";

const sha256 = "9".repeat(64);
const source = "int scale(int x) { return x * 7 + 3; }\n";
const code = Buffer.from(compiledBytes(source, "scale")).toString("hex");
const fn = functionId(sha256, "0x1000");
const toolchain = { cc: "gcc", flags: ["-O2"] };

let store: GraphStore;
beforeEach(() => {
  store = new GraphStore(":memory:");
  loadAnalysis(store, "target", {
    tool: { name: "test", version: "1" },
    sha256,
    functions: [{ address: "0x1000", size: code.length / 2, label: "FUN_00001000", thunk: false, code }],
    calls: [],
    strings: [],
    limitations: [],
  });
});
afterEach(() => store.close());

describe("verifyRewrite", () => {
  it("marks a rewrite that recompiles to the original as verified", async () => {
    const h = proposeRewrite(store, fn, { language: "c", source, name: "scale" }, "agent");
    expect(h.confidence).toBe("guessed");
    const { hypothesis } = await verifyRewrite(store, h.id, toolchain);
    expect(hypothesis).toMatchObject({ confidence: "verified", verification: { check: "recompile", result: "pass" } });
  });

  it("records a mismatch with its details and leaves the confidence as it was", async () => {
    const h = proposeRewrite(
      store,
      fn,
      { language: "c", source: source.replace("+ 3", "+ 4"), name: "scale" },
      "agent",
    );
    const { hypothesis } = await verifyRewrite(store, h.id, toolchain);
    expect(hypothesis.confidence).toBe("guessed");
    expect(hypothesis.verification).toMatchObject({
      check: "recompile",
      result: "fail",
      details: expect.stringMatching(/differ/),
    });
  });

  it("compiles Ghidra-typed C with Ghidra's types included", async () => {
    const ghidraC = "undefined4 scale(int x) { return x * 7 + 3; }\n";
    const h = proposeRewrite(store, fn, { language: "c", source: ghidraC, name: "scale", prelude: "ghidra" }, "agent");
    expect((await verifyRewrite(store, h.id, toolchain)).hypothesis.confidence).toBe("verified");
  });

  it("keeps one hypothesis per function and source", () => {
    const value = { language: "c" as const, source, name: "scale" };
    expect(proposeRewrite(store, fn, value, "agent").id).toBe(proposeRewrite(store, fn, value, "agent").id);
  });
});
