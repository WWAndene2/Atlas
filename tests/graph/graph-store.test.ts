import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { GraphIntegrityError, GraphStore, SchemaError } from "../../src/graph/index.js";
import { binary, call, callee, evidence, main, nameHypothesis } from "./sample-graph.js";

let store: GraphStore;

beforeEach(() => {
  store = new GraphStore(":memory:");
  store.putNode(binary);
  store.putNode(main);
  store.putNode(callee);
  store.putEvidence(evidence);
});

afterEach(() => store.close());

describe("nodes", () => {
  it("reads back what was written", () => {
    expect(store.getNode(main.id)).toEqual(main);
  });

  it("refuses a record that breaks the schema", () => {
    expect(() => store.putNode({ ...main, address: "401000" })).toThrow(SchemaError);
  });

  it("refuses an ID whose prefix does not match the kind", () => {
    expect(() => store.putNode({ ...main, id: "ty_401000" })).toThrow(GraphIntegrityError);
  });

  it("refuses a node whose binary is not in the graph", () => {
    expect(() => store.putNode({ ...main, id: "fn_1", binary: "bin_other" })).toThrow(GraphIntegrityError);
  });
});

describe("edges", () => {
  it("are found from both ends", () => {
    store.putEdge(call);
    expect(store.edgesFrom(main.id, "calls")).toEqual([call]);
    expect(store.edgesTo(callee.id)).toEqual([call]);
  });

  it("refuse an end that is not in the graph", () => {
    expect(() => store.putEdge({ ...call, to: "fn_missing" })).toThrow(GraphIntegrityError);
  });
});

describe("evidence", () => {
  const engineEvidence = {
    schema_version: 1 as const,
    id: `evd_${"b".repeat(16)}`,
    source: "engine" as const,
    summary: "function list of bin_lua",
    created_at: "2026-11-04T12:00:00Z",
  };

  it("from an engine is accepted with the engine and its version", () => {
    const record = { ...engineEvidence, tool: { name: "ghidra", version: "12.1.4" } };
    store.putEvidence(record);
    expect(store.getEvidence(record.id)).toEqual(record);
  });

  it("from an engine is refused without naming the engine", () => {
    expect(() => store.putEvidence(engineEvidence)).toThrow(SchemaError);
  });
});

describe("hypotheses", () => {
  it("are proposed and read back by node", () => {
    store.proposeHypothesis(nameHypothesis);
    expect(store.hypothesesFor(main.id, "name")).toEqual([nameHypothesis]);
  });

  it("cannot be proposed as verified or rejected by an agent", () => {
    expect(() => store.proposeHypothesis({ ...nameHypothesis, confidence: "verified" })).toThrow(GraphIntegrityError);
    expect(() => store.proposeHypothesis({ ...nameHypothesis, confidence: "rejected" })).toThrow(GraphIntegrityError);
    expect(() =>
      store.proposeHypothesis({ ...nameHypothesis, verification: { check: "symbols", result: "pass" } }),
    ).toThrow(GraphIntegrityError);
  });

  it("cannot be proposed twice under one ID", () => {
    store.proposeHypothesis(nameHypothesis);
    expect(() => store.proposeHypothesis(nameHypothesis)).toThrow(GraphIntegrityError);
  });

  it("take the verification loop's outcome", () => {
    store.proposeHypothesis(nameHypothesis);
    const updated = store.recordVerification(nameHypothesis.id, {
      confidence: "verified",
      verification: { check: "symbols", result: "pass" },
    });
    expect(updated.confidence).toBe("verified");
    expect(store.getHypothesis(nameHypothesis.id)).toEqual(updated);
  });
});

describe("transactions", () => {
  it("write nothing when the work fails", () => {
    expect(() =>
      store.transaction(() => {
        store.putEdge(call);
        store.putEdge({ ...call, to: "fn_missing" });
      }),
    ).toThrow(GraphIntegrityError);
    expect(store.edgesFrom(main.id)).toEqual([]);
  });
});
