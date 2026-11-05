// Before the behaviour checks set a rewrite's compiled code beside the original's, its calls are linked to the
// original's callees: a compiled object leaves each call's target as a relocation naming a symbol; that symbol is
// resolved to a function of the binary (Ghidra's FUN_<address>, an engine label, or a name hypothesis), and the call
// is patched to jump there, so both versions call the same addresses (which the checks then model as opaque
// callees). Each callee's arity comes from its prototype in the rewrite's source: the checks compare that many
// arguments per call, none when the prototype says nothing (f() or no declaration).
import type { GraphStore } from "../graph/index.js";
import type { Relocation } from "../verify/recompile/object-file.js";

export interface LinkedCode {
  code: Uint8Array;
  /** Callee address (hex) to its number of parameters, null when the source does not say. */
  arity: Record<string, number | null>;
  /** Call targets naming no function of the binary. */
  unresolved: string[];
}

function arityIn(source: string, name: string): number | null {
  const escaped = name.replace(/[$]/g, "\\$");
  const m = new RegExp(`\\b${escaped}\\s*\\(([^()]*(?:\\([^()]*\\)[^()]*)*)\\)\\s*;`).exec(source);
  if (m === null) return null;
  const params = (m[1] ?? "").trim();
  if (params === "") return null;
  if (params === "void") return 0;
  if (params.includes("...")) return null;
  // Commas at depth 0 (function-pointer parameters carry their own parentheses).
  let depth = 0;
  let count = 1;
  for (const c of params) {
    if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (c === "," && depth === 0) count++;
  }
  return count;
}

function resolve(store: GraphStore, binary: string, symbol: string): bigint | undefined {
  const fun = /^FUN_([0-9a-f]+)$/i.exec(symbol);
  if (fun !== null) return BigInt(`0x${fun[1]}`);
  for (const f of store.nodesOfKind("function")) {
    if (f.binary !== binary || f.address === undefined) continue;
    if (f.label === symbol) return BigInt(f.address);
    if (store.hypothesesFor(f.id, "name").some((h) => h.value === symbol && h.confidence !== "rejected")) {
      return BigInt(f.address);
    }
  }
  return undefined;
}

/** `code` as compiled at `address`, its direct calls and tail jumps patched to the binary's callees. */
export function linkCalls(
  store: GraphStore,
  binary: string,
  code: Uint8Array,
  relocations: Relocation[],
  address: number,
  source: string,
): LinkedCode {
  const out = new Uint8Array(code);
  const view = new DataView(out.buffer);
  const arity: Record<string, number | null> = {};
  const unresolved: string[] = [];
  for (const r of relocations) {
    const opcode = out[r.offset - 1];
    const branch = (opcode === 0xe8 || opcode === 0xe9) && /PLT32|PC32/.test(r.type ?? "");
    if (!branch || r.symbol === undefined) continue;
    const target = resolve(store, binary, r.symbol);
    if (target === undefined) {
      unresolved.push(r.symbol);
      continue;
    }
    const rel = Number(target) - (address + r.offset + 4);
    if (rel < -0x80000000 || rel > 0x7fffffff) {
      unresolved.push(r.symbol);
      continue;
    }
    view.setInt32(r.offset, rel, true);
    arity[`0x${target.toString(16)}`] = arityIn(source, r.symbol);
  }
  return { code: out, arity, unresolved };
}
