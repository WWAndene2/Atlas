import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { binaryId, functionId, loadAnalysis, stringId } from "../../src/orchestrator/load-binary.js";
import type { EngineAnalysis } from "../../src/tools/engine-analysis.js";

const sha256 = "d".repeat(64);
const now = new Date("2026-11-04T12:00:00Z");

function analysis(name: string, calls: EngineAnalysis["calls"]): EngineAnalysis {
  return {
    tool: { name, version: "1.0" },
    sha256,
    functions: [
      { address: "0x1000", size: 16, label: "FUN_00001000", thunk: false },
      { address: "0x1010", size: 8, label: "FUN_00001010", thunk: false },
      { address: "0x1020", size: 8, label: "FUN_00001020", thunk: false },
    ],
    calls,
    strings: [{ address: "0x3000", value: "hello", readers: ["0x1000"] }],
    limitations: ["test data"],
  };
}

let store: GraphStore;
beforeEach(() => (store = new GraphStore(":memory:")));
afterEach(() => store.close());

describe("loadAnalysis", () => {
  it("writes the binary, its functions and calls, backed by engine evidence", () => {
    const result = loadAnalysis(store, "/x/lua.stripped", analysis("ghidra", [{ from: "0x1000", to: "0x1010" }]), now);
    expect(result).toMatchObject({ binary: binaryId(sha256), functions: 3, calls: 1, strings: 1 });
    expect(store.getNode(stringId(sha256, "0x3000"))).toMatchObject({ kind: "string", label: "hello" });
    expect(store.edgesTo(stringId(sha256, "0x3000"), "reads")[0]?.from).toBe(functionId(sha256, "0x1000"));
    expect(store.getNode(result.binary)).toMatchObject({ kind: "binary", label: "lua.stripped" });
    expect(store.getNode(functionId(sha256, "0x1010"))).toMatchObject({ kind: "function", address: "0x1010", size: 8 });
    const [edge] = store.edgesFrom(functionId(sha256, "0x1000"), "calls");
    expect(edge?.evidence).toEqual([result.evidence]);
    expect(store.getEvidence(result.evidence)).toMatchObject({
      source: "engine",
      tool: { name: "ghidra", version: "1.0" },
    });
  });

  it("is idempotent for the same engine", () => {
    const run = analysis("ghidra", [{ from: "0x1000", to: "0x1010" }]);
    const first = loadAnalysis(store, "/x/lua", run, now);
    const second = loadAnalysis(store, "/x/lua", run, now);
    expect(second.evidence).toBe(first.evidence);
    expect(store.allRecords("evidence")).toHaveLength(1);
    expect(store.edgesFrom(functionId(sha256, "0x1000"))[0]?.evidence).toEqual([first.evidence]);
  });

  it("adds a second engine's evidence to the calls both engines found", () => {
    const a = loadAnalysis(store, "/x/lua", analysis("ghidra", [{ from: "0x1000", to: "0x1010" }]), now);
    const b = loadAnalysis(
      store,
      "/x/lua",
      analysis("rizin", [
        { from: "0x1000", to: "0x1010" },
        { from: "0x1000", to: "0x1020" },
      ]),
      now,
    );
    const edges = store.edgesFrom(functionId(sha256, "0x1000"), "calls");
    expect(edges.find((e) => e.to === functionId(sha256, "0x1010"))?.evidence).toEqual([a.evidence, b.evidence].sort());
    expect(edges.find((e) => e.to === functionId(sha256, "0x1020"))?.evidence).toEqual([b.evidence]);
  });
});
