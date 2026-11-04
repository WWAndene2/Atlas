// A small graph shared by the graph tests: one binary, two functions, one call, one piece of evidence.
import type { Evidence, GraphEdge, GraphNode, Hypothesis } from "../../src/graph/index.js";

export const binary: GraphNode = { schema_version: 1, id: "bin_lua", kind: "binary", label: "lua" };
export const main: GraphNode = {
  schema_version: 1,
  id: "fn_401000",
  kind: "function",
  binary: "bin_lua",
  address: "0x401000",
  size: 64,
  label: "sub_401000",
};
export const callee: GraphNode = {
  schema_version: 1,
  id: "fn_401040",
  kind: "function",
  binary: "bin_lua",
  address: "0x401040",
};
export const evidence: Evidence = {
  schema_version: 1,
  id: `ev_${"a".repeat(64)}`,
  source: "rea",
  summary: "call graph of bin_lua",
  created_at: "2026-11-04T12:00:00Z",
};
export const call: GraphEdge = {
  schema_version: 1,
  from: main.id,
  to: callee.id,
  kind: "calls",
  evidence: [evidence.id],
};
export const nameHypothesis: Hypothesis = {
  schema_version: 1,
  id: "hyp_0123456789abcdef",
  node: main.id,
  kind: "name",
  value: "main",
  confidence: "inferred",
  evidence: [evidence.id],
  author: { agent: "namer/test" },
};
