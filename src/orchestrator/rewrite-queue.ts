// The functions of a binary still to rewrite, in the order to hand them to agents: callees before callers, so an
// agent finds its callees' verified prototypes in its task. Import stubs (thunks) are left out, and a function counts
// as done when a verified rewrite covers it, alone or inside a run.
import type { GraphNode, GraphStore } from "../graph/index.js";
import { isRewriteValue } from "../verify/recompile/rewrite-value.js";

export interface QueuedFunction {
  id: string;
  address?: string;
  label?: string;
  size?: number;
  /** Callees still open: a cycle in the call graph leaves some, which then come earlier by address. */
  openCallees: number;
}

/** Functions of the binary covered by a verified rewrite: the function itself, or every function of a run. */
export function verifiedFunctions(store: GraphStore, binary: string): Set<string> {
  const functions = store.nodesOfKind("function").filter((n) => n.binary === binary && n.address !== undefined);
  const done = new Set<string>();
  for (const fn of functions) {
    for (const h of store.hypothesesFor(fn.id, "rewrite")) {
      if (h.confidence !== "verified" || !isRewriteValue(h.value)) continue;
      done.add(fn.id);
      const last = h.value.last === undefined ? undefined : store.getNode(h.value.last.node);
      if (last?.address === undefined || fn.address === undefined) continue;
      const [from, to] = [BigInt(fn.address), BigInt(last.address)];
      for (const n of functions) if (BigInt(n.address ?? 0) >= from && BigInt(n.address ?? 0) <= to) done.add(n.id);
    }
  }
  return done;
}

export function rewriteQueue(store: GraphStore, binary: string): QueuedFunction[] {
  const done = verifiedFunctions(store, binary);
  const open = store
    .nodesOfKind("function")
    .filter((n) => n.binary === binary && n.thunk !== true && n.code !== undefined && !done.has(n.id))
    .sort((a, b) => (BigInt(a.address ?? 0) < BigInt(b.address ?? 0) ? -1 : 1));
  const isOpen = new Set(open.map((n) => n.id));
  const callees = (n: GraphNode): string[] =>
    store
      .edgesFrom(n.id, "calls")
      .map((e) => e.to)
      .filter((to) => isOpen.has(to) && to !== n.id);
  // Depth-first post-order over the open part of the call graph: a function after all the callees it can reach.
  const order: GraphNode[] = [];
  const state = new Map<string, "visiting" | "done">();
  const byId = new Map(open.map((n) => [n.id, n]));
  const visit = (n: GraphNode): void => {
    state.set(n.id, "visiting");
    for (const c of callees(n)) {
      if (state.get(c) === undefined) visit(byId.get(c) as GraphNode);
    }
    state.set(n.id, "done");
    order.push(n);
  };
  for (const n of open) if (state.get(n.id) === undefined) visit(n);
  const position = new Map(order.map((n, i) => [n.id, i]));
  return order.map((n) => ({
    id: n.id,
    ...(n.address !== undefined ? { address: n.address } : {}),
    ...(n.label !== undefined ? { label: n.label } : {}),
    ...(n.size !== undefined ? { size: n.size } : {}),
    openCallees: callees(n).filter((c) => (position.get(c) ?? 0) > (position.get(n.id) ?? 0)).length,
  }));
}
