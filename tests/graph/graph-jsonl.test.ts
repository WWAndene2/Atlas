import { describe, expect, it } from "vitest";
import { GraphStore, exportJsonl, importJsonl } from "../../src/graph/index.js";
import { binary, call, callee, evidence, main, nameHypothesis } from "./sample-graph.js";

function sampleStore(): GraphStore {
  const store = new GraphStore(":memory:");
  // Written in a scrambled order on purpose: the export's order must not depend on it.
  store.putNode(binary);
  store.putNode(callee);
  store.putNode(main);
  store.putEvidence(evidence);
  store.putEdge(call);
  store.proposeHypothesis(nameHypothesis);
  store.recordVerification(nameHypothesis.id, {
    confidence: "verified",
    verification: { check: "symbols", result: "pass" },
  });
  return store;
}

describe("JSONL export", () => {
  it("survives a round trip unchanged, verification outcome included", () => {
    const original = sampleStore();
    const text = exportJsonl(original);
    const copy = new GraphStore(":memory:");
    importJsonl(copy, text);
    expect(exportJsonl(copy)).toBe(text);
    expect(copy.getHypothesis(nameHypothesis.id)?.confidence).toBe("verified");
    original.close();
    copy.close();
  });

  it("puts binaries first and one record per line", () => {
    const store = sampleStore();
    const lines = exportJsonl(store).trimEnd().split("\n");
    expect(lines).toHaveLength(6);
    expect(JSON.parse(lines[0] ?? "")).toEqual({ type: "node", record: binary });
    store.close();
  });

  it("imports nothing when one line is invalid", () => {
    const store = sampleStore();
    const broken = exportJsonl(store).replace('"kind":"calls"', '"kind":"jumps"');
    const copy = new GraphStore(":memory:");
    expect(() => importJsonl(copy, broken)).toThrow();
    expect(copy.getNode(binary.id)).toBeUndefined();
    store.close();
    copy.close();
  });
});
