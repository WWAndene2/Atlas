// atlas match graph <documented.sqlite> [--binary <bin_>]: knowledge carried over from a documented graph.
import { existsSync } from "node:fs";
import { GraphStore } from "../../graph/index.js";
import { carryKnowledge } from "../../orchestrator/carry-knowledge.js";
import { CliError, type Output } from "../output.js";

function onlyBinary(store: GraphStore, binary: string | undefined, what: string): string {
  const binaries = store.nodesOfKind("binary").filter((b) => binary === undefined || b.id === binary);
  if (binaries.length !== 1) {
    throw new CliError(
      "usage",
      binaries.length === 0 ? `no binary in ${what}` : `several binaries in ${what}: name one with --binary`,
    );
  }
  return (binaries[0] as { id: string }).id;
}

export async function runMatchGraph(store: GraphStore, args: string[], binary: string | undefined): Promise<Output> {
  const [what, path, ...extra] = args;
  if (what !== "graph" || path === undefined || extra.length > 0) {
    throw new CliError("usage", "usage: atlas match graph <documented graph.sqlite> [--binary <bin_>]");
  }
  if (!existsSync(path)) throw new CliError("not_found", `no graph ${path}`);
  const target = onlyBinary(store, binary, "this graph");
  const source = new GraphStore(path);
  try {
    const outcome = await carryKnowledge(store, target, source, onlyBinary(source, undefined, path));
    return {
      data: outcome,
      text:
        `${outcome.matched} of ${outcome.compared} functions matched (${outcome.ambiguous} ambiguous, left out): ` +
        `${outcome.names} names and ${outcome.rewrites} verified rewrites carried over (rewrites to verify: atlas verify all)`,
    };
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError("failed", (error as Error).message);
  } finally {
    source.close();
  }
}
