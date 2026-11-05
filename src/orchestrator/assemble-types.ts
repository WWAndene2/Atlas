// Struct types assembled from the fields inferred per function (infer-fields.ts): arguments whose accessed fields
// mostly coincide (at least half of an argument's fields already in a type, and no field at the same offset with
// another width) are taken to point to the same struct, whose layout is the union of their fields. Each struct is a
// type node (ty_) with a type hypothesis (inferred) holding the layout and the arguments using it; an agent writing
// C then declares one struct for all of them instead of one per function. Arguments are taken widest first, so a
// struct forms around its most complete view. Measured on Lua against DWARF (docs/ROADMAP.md, M4).
import { createHash } from "node:crypto";
import type { GraphStore } from "../graph/index.js";
import type { FieldsArgument } from "./infer-fields.js";

/** Share of an argument's fields that must already be in a type for the argument to join it. */
export const MIN_SHARED = 0.5;

export interface TypesOutcome {
  binary: string;
  arguments: number;
  types: { id: string; size: number; fields: number; used_by: number }[];
}

interface Use {
  function: string;
  register: string;
  fields: FieldsArgument["fields"];
}

const key = (f: { offset: number; size: number }) => `${f.offset}:${f.size}`;

export function assembleTypes(store: GraphStore, binary: string): TypesOutcome {
  const uses: Use[] = [];
  for (const fn of store.nodesOfKind("function").filter((f) => f.binary === binary)) {
    for (const h of store.hypothesesFor(fn.id, "signature")) {
      if (h.author.agent !== "typer/angr" || h.confidence === "rejected") continue;
      for (const a of (h.value as { arguments: FieldsArgument[] }).arguments) {
        const fields = a.fields.filter((f) => f.offset >= 0);
        // One field says too little to tell one struct from another.
        if (fields.length >= 2) uses.push({ function: fn.id, register: a.register, fields });
      }
    }
  }
  uses.sort((a, b) => b.fields.length - a.fields.length || (a.function < b.function ? -1 : 1));
  const types: {
    layout: Map<string, { offset: number; size: number; access: string }>;
    widths: Map<number, number>;
    users: Use[];
  }[] = [];
  for (const use of uses) {
    let best: (typeof types)[number] | undefined;
    let bestShare = 0;
    for (const t of types) {
      if (use.fields.some((f) => t.widths.has(f.offset) && t.widths.get(f.offset) !== f.size)) continue;
      const share = use.fields.filter((f) => t.layout.has(key(f))).length / use.fields.length;
      if (share > bestShare) {
        best = t;
        bestShare = share;
      }
    }
    if (best === undefined || bestShare < MIN_SHARED) {
      best = { layout: new Map(), widths: new Map(), users: [] };
      types.push(best);
    }
    for (const f of use.fields) {
      const existing = best.layout.get(key(f));
      const access = existing === undefined || existing.access === f.access ? f.access : "rw";
      best.layout.set(key(f), { offset: f.offset, size: f.size, access });
      best.widths.set(f.offset, f.size);
    }
    best.users.push(use);
  }
  const outcome: TypesOutcome = { binary, arguments: uses.length, types: [] };
  store.transaction(() => {
    types.forEach((t, n) => {
      const fields = [...t.layout.values()].sort((a, b) => a.offset - b.offset || a.size - b.size);
      const size = Math.max(...fields.map((f) => f.offset + f.size));
      const id = `ty_${binary.slice(4)}_${n}`;
      store.putNode({ schema_version: 1, id, kind: "type", binary, size, label: `struct_${n}` });
      const value = {
        layout: fields,
        size_at_least: size,
        used_by: t.users.map((u) => ({ function: u.function, register: u.register })),
      };
      const hyp = `hyp_${createHash("sha256")
        .update(`${id}\ntype\n${JSON.stringify(value)}`)
        .digest("hex")
        .slice(0, 32)}`;
      if (store.getHypothesis(hyp) === undefined) {
        store.proposeHypothesis({
          schema_version: 1,
          id: hyp,
          node: id,
          kind: "type",
          value,
          confidence: "inferred",
          evidence: [...new Set(t.users.map((u) => u.function))].slice(0, 64),
          author: { agent: "typer/assemble" },
        });
      }
      outcome.types.push({ id, size, fields: fields.length, used_by: t.users.length });
    });
  });
  return outcome;
}
