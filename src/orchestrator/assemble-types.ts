// Struct types assembled from the fields inferred per function (infer-fields.ts). Arguments handed unchanged to a
// callee are joined with its parameter first; then arguments whose accessed fields
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
  const all = new Map<string, Use>();
  const links: [string, string][] = [];
  for (const fn of store.nodesOfKind("function").filter((f) => f.binary === binary)) {
    for (const h of store.hypothesesFor(fn.id, "signature")) {
      if (h.author.agent !== "typer/angr" || h.confidence === "rejected") continue;
      const value = h.value as {
        arguments: FieldsArgument[];
        passes?: { callee: string; callee_register: string; register: string }[];
      };
      for (const a of value.arguments) {
        all.set(`${fn.id}/${a.register}`, {
          function: fn.id,
          register: a.register,
          fields: a.fields.filter((f) => f.offset >= 0),
        });
      }
      for (const p of value.passes ?? []) links.push([`${fn.id}/${p.register}`, `${p.callee}/${p.callee_register}`]);
    }
  }
  // An argument handed unchanged to a callee points to the struct the callee's parameter points to: such arguments
  // are joined first (union-find), unless their fields disagree in width at one offset (a union, or a wrong link).
  const parent = new Map<string, string>();
  const find = (k: string): string => {
    const p = parent.get(k) ?? k;
    if (p === k) return k;
    const root = find(p);
    parent.set(k, root);
    return root;
  };
  const groupFields = new Map<string, Use["fields"]>([...all].map(([k, u]) => [k, u.fields]));
  for (const [a, b] of links) {
    if (!all.has(a) || !all.has(b)) continue;
    const [ra, rb] = [find(a), find(b)];
    if (ra === rb) continue;
    const fa = groupFields.get(ra) ?? [];
    const fb = groupFields.get(rb) ?? [];
    if (fa.some((x) => fb.some((y) => x.offset === y.offset && x.size !== y.size))) continue;
    parent.set(rb, ra);
    const merged = new Map([...fa, ...fb].map((f) => [key(f), f]));
    groupFields.set(ra, [...merged.values()]);
  }
  const groups = new Map<string, { fields: Use["fields"]; users: Use[] }>();
  for (const [k, u] of all) {
    const root = find(k);
    const g = groups.get(root) ?? { fields: groupFields.get(root) ?? [], users: [] };
    g.users.push(u);
    groups.set(root, g);
  }
  // One field says too little to tell one struct from another.
  const uses = [...groups.values()]
    .filter((g) => g.fields.length >= 2)
    .sort(
      (a, b) =>
        b.fields.length - a.fields.length || ((a.users[0]?.function ?? "") < (b.users[0]?.function ?? "") ? -1 : 1),
    );
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
    best.users.push(...use.users);
  }
  const outcome: TypesOutcome = { binary, arguments: uses.reduce((n, g) => n + g.users.length, 0), types: [] };
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
