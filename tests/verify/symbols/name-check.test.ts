import { describe, expect, it } from "vitest";
import { GraphStore } from "../../../src/graph/index.js";
import { functionId, loadAnalysis } from "../../../src/orchestrator/load-binary.js";
import { proposeName } from "../../../src/orchestrator/propose-name.js";
import { checkName, normaliseName } from "../../../src/verify/symbols/name-check.js";

describe("normaliseName", () => {
  it("removes what compilers add to source names", () => {
    expect(normaliseName("_luaL_checkinteger")).toBe("lual_checkinteger");
    expect(normaliseName("reallymarkobject.isra.0")).toBe("reallymarkobject");
    expect(normaliseName("luaV_execute.part.0.cold")).toBe("luav_execute");
  });
});

describe("checkName", () => {
  it("verifies a matching name, rejects another, and leaves a name without key inconclusive", () => {
    const store = new GraphStore(":memory:");
    const sha256 = "6".repeat(64);
    loadAnalysis(store, "t", {
      tool: { name: "test", version: "1" },
      sha256,
      functions: [{ address: "0x10", size: 4, label: "FUN_10", thunk: false }],
      calls: [],
      strings: [],
      limitations: [],
    });
    const fn = functionId(sha256, "0x10");
    const right = proposeName(store, fn, "luaH_get", "agent");
    const wrong = proposeName(store, fn, "luaH_set", "agent");
    const loose = proposeName(store, fn, "anything", "agent");
    expect(checkName(store, right, "luaH_get.isra.0")).toBe("verified");
    expect(checkName(store, wrong, "luaH_get")).toBe("rejected");
    expect(checkName(store, loose, undefined)).toBe("no_key");
    expect(store.getHypothesis(right.id)?.confidence).toBe("verified");
    expect(store.getHypothesis(wrong.id)).toMatchObject({
      confidence: "rejected",
      verification: { details: "the symbol is luaH_get" },
    });
    store.close();
  });
});
