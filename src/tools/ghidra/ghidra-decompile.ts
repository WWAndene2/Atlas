// Reads the JSON document written by scripts/AtlasDecompile.java: each function's C, or why Ghidra could not
// decompile it. Checked field by field, as everything that comes from a run on target data.
import { GhidraExportError } from "./ghidra-export.js";

export interface DecompiledFunction {
  address: string;
  /** Ghidra's name for the function (raw label, untrusted target data when it comes from symbols). */
  label: string;
  /** The decompiled C, when Ghidra produced it. */
  c?: string;
  /** Why there is no C. */
  error?: string;
}

export function parseGhidraDecompile(text: string): DecompiledFunction[] {
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch (error) {
    throw new GhidraExportError(`decompile output is not JSON (${(error as Error).message})`);
  }
  const r = root as { format?: unknown; format_version?: unknown; functions?: unknown };
  if (r.format !== "atlas-ghidra-decompile" || r.format_version !== 1 || !Array.isArray(r.functions)) {
    throw new GhidraExportError("unknown decompile format");
  }
  return r.functions.map((item: unknown, i) => {
    const f = item as Record<string, unknown>;
    if (typeof f !== "object" || f === null) throw new GhidraExportError(`functions[${i}] is not an object`);
    if (typeof f.address !== "string" || !/^0x[0-9a-f]+$/.test(f.address) || typeof f.label !== "string") {
      throw new GhidraExportError(`functions[${i}] has no valid address and label`);
    }
    if (typeof f.c === "string") return { address: f.address, label: f.label, c: f.c };
    return { address: f.address, label: f.label, error: typeof f.error === "string" ? f.error : "no C" };
  });
}
