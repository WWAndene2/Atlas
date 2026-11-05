// TypeScript mirror of the JSON Schemas in schema/. The schemas are the contract; these types must follow them.

export const SCHEMA_VERSION = 1 as const;

export type NodeKind =
  "binary" | "function" | "type" | "global" | "string" | "system" | "format" | "shader" | "resource" | "unknown";

export interface GraphNode {
  schema_version: typeof SCHEMA_VERSION;
  id: string;
  kind: NodeKind;
  binary?: string;
  address?: string;
  size?: number;
  /** On a binary: the CPU its code runs on (Atlas's architecture names, src/tools/engine-analysis.ts). */
  architecture?: "x86" | "x86_64" | "arm-v5te" | "arm-v6k" | "arm-v7" | "arm64" | "mips" | "mipsel" | "ppc" | "ppc64";
  /** On a function: the file's bytes from its entry up to the next function, hex; the recompile check's reference. */
  code?: string;
  /** On a function: code no source function of its own produces (linker stubs; pieces split off another function). */
  generated?: "linker" | "fragment";
  /** On a function: a stub that only jumps elsewhere. */
  thunk?: boolean;
  label?: string;
}

export type EdgeKind = "calls" | "reads" | "writes" | "contains" | "draws" | "loads" | "matches";

export interface GraphEdge {
  schema_version: typeof SCHEMA_VERSION;
  from: string;
  to: string;
  kind: EdgeKind;
  evidence: string[];
}

export type EvidenceSource = "rea" | "engine" | "trace" | "capture" | "verification";

export interface Evidence {
  schema_version: typeof SCHEMA_VERSION;
  id: string;
  source: EvidenceSource;
  summary: string;
  /** The engine that produced it; required when source is "engine". */
  tool?: { name: string; version: string };
  limitations?: string[];
  created_at: string;
}

export type HypothesisKind =
  "name" | "signature" | "type" | "summary" | "system" | "format" | "rewrite" | "match" | "toolchain";

export type Confidence = "guessed" | "inferred" | "observed" | "verified" | "rejected";

export interface Hypothesis {
  schema_version: typeof SCHEMA_VERSION;
  id: string;
  node: string;
  kind: HypothesisKind;
  value: unknown;
  confidence: Confidence;
  evidence: string[];
  author: { agent: string; task?: string };
  verification?: {
    check?: "structural" | "differential" | "trace_types" | "symbols" | "parser_run" | "recompile";
    result?: "pass" | "fail" | "inconclusive";
    details?: string;
  };
}

/** The node kind each ID prefix stands for (AGENTS.md section 4.2). */
export const NODE_ID_PREFIX: Record<NodeKind, string> = {
  binary: "bin_",
  function: "fn_",
  type: "ty_",
  global: "gl_",
  string: "str_",
  system: "sys_",
  format: "fmt_",
  shader: "sh_",
  resource: "res_",
  unknown: "unk_",
};
