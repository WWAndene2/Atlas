// Systems (M5): a binary's functions grouped into the modules they came from. Without LTO a compiler emits each source
// file's functions together, and functions of one file call each other more than they call the rest; so the
// functions, in address order, are cut into contiguous runs maximising modularity over a graph of their calls plus a
// link between neighbours (dynamic programming over cut points: exact for contiguous runs). Each run becomes a system
// node (sys_) and each member gets a system hypothesis (inferred) pointing at it; an agent then names and summarises
// a system from what `atlas get system` shows (members, strings, outside calls) with `atlas propose summary`.
// Measured on Lua x86-64 against its source files (docs/ROADMAP.md, M5).
import { createHash } from "node:crypto";
import type { GraphNode, GraphStore } from "../graph/index.js";
import { NotFoundError } from "./function-context.js";

/** Weight of the link between functions next to each other in the binary, against 1 per call. */
export const NEIGHBOUR_WEIGHT = 2;
/** Modularity resolution: higher cuts more, smaller systems. */
export const RESOLUTION = 1;
/** Longest run considered, in functions (bounds the search to n x MAX_RUN). */
const MAX_RUN = 150;

export interface SystemsOutcome {
  binary: string;
  systems: { id: string; first: string; last: string; functions: number }[];
}

export function systemId(binary: string, firstAddress: string): string {
  return `sys_${binary.slice(4)}_${BigInt(firstAddress).toString(16)}`;
}

/** Contiguous runs (start indexes and ends) of `functions`, in address order, maximising modularity. */
export function segment(functions: GraphNode[], callees: (f: GraphNode) => string[]): [number, number][] {
  const n = functions.length;
  const index = new Map(functions.map((f, i) => [f.id, i]));
  const weight = Array.from({ length: n }, () => new Map<number, number>());
  const link = (a: number, b: number, w: number) => {
    if (a === b) return;
    weight[a]?.set(b, (weight[a]?.get(b) ?? 0) + w);
    weight[b]?.set(a, (weight[b]?.get(a) ?? 0) + w);
  };
  const called = new Set<string>();
  functions.forEach((f, i) => {
    for (const to of callees(f)) {
      const j = index.get(to);
      const key = i < (j ?? -1) ? `${i}-${j}` : `${j}-${i}`;
      if (j === undefined || called.has(key)) continue;
      called.add(key);
      link(i, j, 1);
    }
    if (i + 1 < n) link(i, i + 1, NEIGHBOUR_WEIGHT);
  });
  const degree = weight.map((m) => [...m.values()].reduce((a, b) => a + b, 0));
  const total = degree.reduce((a, b) => a + b, 0) / 2;
  if (total === 0) return n === 0 ? [] : [[0, n]];
  const prefix = [0];
  for (const d of degree) prefix.push((prefix.at(-1) ?? 0) + d);
  const best = new Array<number>(n + 1).fill(-Infinity);
  const back = new Array<number>(n + 1).fill(0);
  best[0] = 0;
  for (let j = 1; j <= n; j++) {
    let inside = 0;
    for (let i = j - 1; i >= Math.max(0, j - MAX_RUN); i--) {
      for (const [k, w] of weight[i] ?? []) if (k > i && k < j) inside += w;
      const d = (prefix[j] ?? 0) - (prefix[i] ?? 0);
      const q = (best[i] ?? 0) + inside / total - RESOLUTION * (d / (2 * total)) ** 2;
      if (q > (best[j] ?? -Infinity)) {
        best[j] = q;
        back[j] = i;
      }
    }
  }
  const runs: [number, number][] = [];
  for (let j = n; j > 0; j = back[j] ?? 0) runs.unshift([back[j] ?? 0, j]);
  return runs;
}

export function clusterSystems(store: GraphStore, binary: string): SystemsOutcome {
  const functions = store
    .nodesOfKind("function")
    .filter((f) => f.binary === binary && f.address !== undefined && f.thunk !== true && f.generated === undefined)
    .sort((a, b) => (BigInt(a.address as string) < BigInt(b.address as string) ? -1 : 1));
  const runs = segment(functions, (f) => store.edgesFrom(f.id, "calls").map((e) => e.to));
  const evidence = `evd_${createHash("sha256").update(`systems\n${binary}`).digest("hex").slice(0, 32)}`;
  const outcome: SystemsOutcome = { binary, systems: [] };
  store.transaction(() => {
    store.putEvidence({
      schema_version: 1,
      id: evidence,
      source: "engine",
      tool: { name: "atlas-systems", version: "1" },
      summary: `systems of ${binary}: ${functions.length} functions in address order cut into ${runs.length} runs by call modularity`,
      limitations: [
        "contiguity assumes no link-time optimisation or reordering; a run can join two small neighbouring files",
      ],
      created_at: new Date().toISOString(),
    });
    for (const [from, to] of runs) {
      const members = functions.slice(from, to);
      const first = members[0] as GraphNode;
      const last = members.at(-1) as GraphNode;
      const id = systemId(binary, first.address as string);
      store.putNode({
        schema_version: 1,
        id,
        kind: "system",
        binary,
        address: first.address as string,
        label: `${first.address}-${last.address}`,
      });
      for (const f of members) {
        const hyp = `hyp_${createHash("sha256").update(`${f.id}\nsystem\n${id}`).digest("hex").slice(0, 32)}`;
        if (store.getHypothesis(hyp) !== undefined) continue;
        store.proposeHypothesis({
          schema_version: 1,
          id: hyp,
          node: f.id,
          kind: "system",
          value: id,
          confidence: "inferred",
          evidence: [evidence],
          author: { agent: "clusterer/modularity" },
        });
      }
      outcome.systems.push({
        id,
        first: first.address as string,
        last: last.address as string,
        functions: members.length,
      });
    }
  });
  return outcome;
}

/** What an agent needs to name and summarise a system: its functions, the strings they use, calls leaving it. */
export function systemContext(store: GraphStore, system: string) {
  const node = store.getNode(system);
  if (node?.kind !== "system") throw new NotFoundError(`no system ${system}`);
  const members = store
    .nodesOfKind("function")
    .filter((f) => f.binary === node.binary && store.hypothesesFor(f.id, "system").some((h) => h.value === system));
  const inside = new Set(members.map((f) => f.id));
  const name = (id: string) =>
    store
      .hypothesesFor(id, "name")
      .filter((h) => h.confidence !== "rejected")
      .map((h) => h.value as string)[0] ?? store.getNode(id)?.label;
  const strings = new Set<string>();
  const outside = new Map<string, string | undefined>();
  for (const f of members) {
    for (const e of store.edgesFrom(f.id, "reads")) {
      const label = store.getNode(e.to)?.label;
      if (label !== undefined) strings.add(label);
    }
    for (const e of store.edgesFrom(f.id, "calls")) if (!inside.has(e.to)) outside.set(e.to, name(e.to));
  }
  return {
    system: node,
    summaries: store.hypothesesFor(system, "summary"),
    functions: members.map((f) => ({ id: f.id, address: f.address, size: f.size, name: name(f.id) })),
    strings: [...strings].slice(0, 200),
    calls_out: [...outside].map(([id, n]) => ({ id, name: n })),
  };
}

/** An agent's name and summary for a system. */
export function proposeSummary(store: GraphStore, system: string, name: string, text: string, author: string) {
  if (store.getNode(system)?.kind !== "system") throw new NotFoundError(`no system ${system}`);
  const value = { name, summary: text };
  const id = `hyp_${createHash("sha256")
    .update(`${system}\nsummary\n${JSON.stringify(value)}`)
    .digest("hex")
    .slice(0, 32)}`;
  const existing = store.getHypothesis(id);
  if (existing !== undefined) return existing;
  const hypothesis = {
    schema_version: 1 as const,
    id,
    node: system,
    kind: "summary" as const,
    value,
    confidence: "guessed" as const,
    evidence: [system],
    author: { agent: author },
  };
  store.proposeHypothesis(hypothesis);
  return hypothesis;
}
