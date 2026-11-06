// Reads the JSON document written by scripts/AtlasExport.java and turns it into an EngineAnalysis. The document comes
// from a process Atlas started on target data, so it is checked field by field before anything is trusted.
import type { EngineAnalysis, EngineCall, EngineFunction, EngineString } from "../engine-analysis.js";

export class GhidraExportError extends Error {
  constructor(message: string) {
    super(`Ghidra export: ${message}`);
    this.name = "GhidraExportError";
  }
}

const HEX = /^0x[0-9a-f]+$/;

function object(value: unknown, where: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new GhidraExportError(`${where} is not an object`);
  return value as Record<string, unknown>;
}

function array(value: unknown, where: string): unknown[] {
  if (!Array.isArray(value)) throw new GhidraExportError(`${where} is not an array`);
  return value;
}

function string(record: Record<string, unknown>, key: string, where: string, pattern?: RegExp): string {
  const value = record[key];
  if (typeof value !== "string" || (pattern !== undefined && !pattern.test(value))) {
    throw new GhidraExportError(`${where}.${key} is invalid`);
  }
  return value;
}

function boolean(record: Record<string, unknown>, key: string, where: string): boolean {
  const value = record[key];
  if (typeof value !== "boolean") throw new GhidraExportError(`${where}.${key} is not a boolean`);
  return value;
}

export function parseGhidraExport(text: string): EngineAnalysis {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new GhidraExportError(`not JSON (${(error as Error).message})`);
  }
  const root = object(parsed, "document");
  if (root.format !== "atlas-ghidra-export" || root.format_version !== 1) {
    throw new GhidraExportError("unknown format or format_version");
  }
  const version = string(root, "ghidra_version", "document");
  const sha256 = string(root, "sha256", "document", /^[0-9a-f]{64}$/);

  // External functions (imports) live in Ghidra's EXTERNAL space: their "addresses" are not in the file, so they are
  // left out, and so are calls to them. Calls reach imports through thunks, which are kept.
  const functions: EngineFunction[] = [];
  const internal = new Set<string>();
  array(root.functions, "functions").forEach((item, i) => {
    const where = `functions[${i}]`;
    const f = object(item, where);
    if (boolean(f, "external", where)) return;
    const size = f.size;
    if (typeof size !== "number" || !Number.isInteger(size) || size < 0)
      throw new GhidraExportError(`${where}.size is invalid`);
    const address = string(f, "address", where, HEX);
    const code = f.code === undefined ? undefined : string(f, "code", where, /^([0-9a-f]{2}){0,65536}$/);
    functions.push({
      address,
      size,
      label: string(f, "label", where),
      thunk: boolean(f, "thunk", where),
      ...(f.generated === "linker" || f.generated === "fragment" ? { generated: f.generated } : {}),
      ...(code !== undefined ? { code } : {}),
    });
    internal.add(address);
  });

  const calls: EngineCall[] = [];
  const seen = new Set<string>();
  array(root.calls, "calls").forEach((item, i) => {
    const where = `calls[${i}]`;
    const c = object(item, where);
    const from = string(c, "from", where, HEX);
    const to = string(c, "to", where, HEX);
    string(c, "site", where, HEX);
    if (!internal.has(from) || !internal.has(to)) return;
    const key = `${from}>${to}`;
    if (seen.has(key)) return;
    seen.add(key);
    calls.push({ from, to });
  });

  const strings: EngineString[] = array(root.strings, "strings").map((item, i) => {
    const where = `strings[${i}]`;
    const s = object(item, where);
    const readers = array(s.readers, `${where}.readers`).map((reader, j) => {
      if (typeof reader !== "string" || !HEX.test(reader))
        throw new GhidraExportError(`${where}.readers[${j}] is invalid`);
      return reader;
    });
    return {
      address: string(s, "address", where, HEX),
      value: string(s, "value", where),
      readers: readers.filter((reader) => internal.has(reader)),
    };
  });

  return {
    tool: { name: "ghidra", version },
    sha256,
    functions,
    calls,
    strings,
    limitations: [
      "Ghidra auto-analysis with default analysers: functions reached only through computed jumps or tables may be missed.",
      "Calls are direct call references; indirect calls through pointers are absent.",
    ],
  };
}
