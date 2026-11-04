// Fills the graph with one engine's analysis of one binary: a binary node, a function node per function, a calls
// edge per caller and callee pair, a string node per string with a reads edge from each function using it, all backed by one evidence record naming the engine and its version.
//
// Loading again, with the same or another engine, adds evidence to what is already there instead of replacing it,
// so a fact two engines agree on ends up carrying both records (the cross-check of roadmap M1 builds on this).
import { createHash } from "node:crypto";
import type { Evidence, GraphEdge, GraphNode, GraphStore } from "../graph/index.js";
import type { EngineAnalysis } from "../tools/engine-analysis.js";

export interface LoadResult {
  binary: string;
  evidence: string;
  functions: number;
  calls: number;
  strings: number;
}

export function binaryId(sha256: string): string {
  return `bin_${sha256.slice(0, 16)}`;
}

export function functionId(sha256: string, address: string): string {
  return `fn_${sha256.slice(0, 16)}_${address.slice(2)}`;
}

export function stringId(sha256: string, address: string): string {
  return `str_${sha256.slice(0, 16)}_${address.slice(2)}`;
}

function union(existing: string[] | undefined, added: string): string[] {
  return [...new Set([...(existing ?? []), added])].sort();
}

export function loadAnalysis(
  store: GraphStore,
  label: string,
  analysis: EngineAnalysis,
  now: Date = new Date(),
): LoadResult {
  const { sha256, tool } = analysis;
  const binary = binaryId(sha256);
  // Same engine, version and file give the same ID, so loading twice does not pile up identical records.
  const evidenceId = `evd_${createHash("sha256").update(`${tool.name}\n${tool.version}\n${sha256}`).digest("hex").slice(0, 32)}`;
  const evidence: Evidence = {
    schema_version: 1,
    id: evidenceId,
    source: "engine",
    tool: { name: tool.name, version: tool.version },
    summary: `${tool.name} ${tool.version}: ${analysis.functions.length} functions, ${analysis.calls.length} calls and ${analysis.strings.length} strings in ${label} (sha256 ${sha256})`,
    limitations: analysis.limitations,
    created_at: now.toISOString(),
  };

  store.transaction(() => {
    store.putEvidence(evidence);
    if (store.getNode(binary) === undefined) {
      store.putNode({ schema_version: 1, id: binary, kind: "binary", label });
    }
    for (const f of analysis.functions) {
      const id = functionId(sha256, f.address);
      // A node already loaded by another engine keeps its fields; the first engine's label and size stay.
      if (store.getNode(id) !== undefined) continue;
      const node: GraphNode = {
        schema_version: 1,
        id,
        kind: "function",
        binary,
        address: f.address,
        size: f.size,
        label: f.label,
        ...(f.thunk ? { thunk: true } : {}),
      };
      store.putNode(node);
    }
    for (const c of analysis.calls) {
      const from = functionId(sha256, c.from);
      const to = functionId(sha256, c.to);
      const existing = store.edgesFrom(from, "calls").find((e) => e.to === to);
      const edge: GraphEdge = {
        schema_version: 1,
        from,
        to,
        kind: "calls",
        evidence: union(existing?.evidence, evidenceId),
      };
      store.putEdge(edge);
    }
    for (const str of analysis.strings) {
      const id = stringId(sha256, str.address);
      if (store.getNode(id) === undefined) {
        store.putNode({ schema_version: 1, id, kind: "string", binary, address: str.address, label: str.value });
      }
      for (const reader of str.readers) {
        const from = functionId(sha256, reader);
        const existing = store.edgesFrom(from, "reads").find((e) => e.to === id);
        store.putEdge({
          schema_version: 1,
          from,
          to: id,
          kind: "reads",
          evidence: union(existing?.evidence, evidenceId),
        });
      }
    }
  });

  return {
    binary,
    evidence: evidenceId,
    functions: analysis.functions.length,
    calls: analysis.calls.length,
    strings: analysis.strings.length,
  };
}
