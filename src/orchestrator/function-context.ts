// What the graph knows about one function: the node, the functions it calls and is called by, the strings it reads,
// and the hypotheses on it. The context an agent works from (AGENTS.md, section 1).
import type { GraphNode, GraphStore, Hypothesis } from "../graph/index.js";

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotFoundError";
  }
}

export interface FunctionContext {
  function: GraphNode;
  callers: GraphNode[];
  callees: GraphNode[];
  strings: GraphNode[];
  hypotheses: Hypothesis[];
}

/**
 * Finds a function by its ID (fn_...) or its address (0x...). An address must match one function only: with several
 * binaries in the graph, `binary` (a bin_ ID) picks one.
 */
export function resolveFunction(store: GraphStore, ref: string, binary?: string): GraphNode {
  if (ref.startsWith("fn_")) {
    const node = store.getNode(ref);
    if (node?.kind !== "function") throw new NotFoundError(`no function ${ref}`);
    return node;
  }
  if (!/^0x[0-9a-fA-F]+$/.test(ref))
    throw new NotFoundError(`${ref} is neither a function ID (fn_...) nor an address (0x...)`);
  const address = `0x${BigInt(ref).toString(16)}`;
  const matches = store
    .nodesOfKind("function")
    .filter((n) => n.address === address && (binary === undefined || n.binary === binary));
  if (matches.length === 0) throw new NotFoundError(`no function at ${address}`);
  if (matches.length > 1) {
    throw new NotFoundError(`${matches.length} functions at ${address}, one per binary; name the binary`);
  }
  return matches[0] as GraphNode;
}

function nodes(store: GraphStore, ids: string[]): GraphNode[] {
  return ids.map((id) => store.getNode(id)).filter((n): n is GraphNode => n !== undefined);
}

export function functionContext(store: GraphStore, fn: GraphNode): FunctionContext {
  return {
    function: fn,
    callers: nodes(
      store,
      store.edgesTo(fn.id, "calls").map((e) => e.from),
    ),
    callees: nodes(
      store,
      store.edgesFrom(fn.id, "calls").map((e) => e.to),
    ),
    strings: nodes(
      store,
      store.edgesFrom(fn.id, "reads").map((e) => e.to),
    ).filter((n) => n.kind === "string"),
    hypotheses: store.hypothesesFor(fn.id),
  };
}
