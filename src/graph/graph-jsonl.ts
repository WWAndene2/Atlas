// JSONL export and import of a graph: one record per line, in a fixed order, so two exports of the same graph are
// byte-identical and can be diffed and reviewed like code.
import type { GraphStore } from "./graph-store.js";
import type { Evidence, GraphEdge, GraphNode, Hypothesis } from "./model.js";

type Line =
  | { type: "node"; record: GraphNode }
  | { type: "edge"; record: GraphEdge }
  | { type: "evidence"; record: Evidence }
  | { type: "hypothesis"; record: Hypothesis };

// Import order matters: nodes before what references them, and binaries first, since every other node names one.
const TABLES = [
  ["nodes", "node"],
  ["evidence", "evidence"],
  ["edges", "edge"],
  ["hypotheses", "hypothesis"],
] as const;

export function exportJsonl(store: GraphStore): string {
  const lines: string[] = [];
  for (const [table, type] of TABLES) {
    const records = store.allRecords(table);
    if (table === "nodes") records.sort((a, b) => binaryFirst(a as GraphNode, b as GraphNode));
    for (const record of records) lines.push(JSON.stringify({ type, record }));
  }
  return lines.length === 0 ? "" : `${lines.join("\n")}\n`;
}

/**
 * Loads an export into `store`, in one transaction: all of it, or nothing. Verification outcomes are restored as
 * they were exported.
 */
export function importJsonl(store: GraphStore, text: string): void {
  store.transaction(() => {
    for (const [index, raw] of text.split("\n").entries()) {
      if (raw.trim() === "") continue;
      const line = JSON.parse(raw) as Line;
      switch (line.type) {
        case "node":
          store.putNode(line.record);
          break;
        case "edge":
          store.putEdge(line.record);
          break;
        case "evidence":
          store.putEvidence(line.record);
          break;
        case "hypothesis":
          store.restoreHypothesis(line.record);
          break;
        default:
          throw new Error(`line ${index + 1}: unknown record type`);
      }
    }
  });
}

function binaryFirst(a: GraphNode, b: GraphNode): number {
  const rank = (node: GraphNode) => (node.kind === "binary" ? 0 : 1);
  return rank(a) - rank(b) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}
