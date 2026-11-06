// atlas propose name <fn_id|0xaddress> <name>, atlas score names --truth <unstripped file> [--binary <bin_>]
import type { GraphStore } from "../../graph/index.js";
import { resolveFunction } from "../../orchestrator/function-context.js";
import { proposeName } from "../../orchestrator/propose-name.js";
import { scoreNames } from "../../orchestrator/score-names.js";
import { CliError, type Output } from "../output.js";

export function runProposeName(store: GraphStore, args: string[], binary: string | undefined, agent?: string): Output {
  const [, ref, name, ...extra] = args;
  if (ref === undefined || name === undefined || extra.length > 0) {
    throw new CliError("usage", "usage: atlas propose name <fn_id|0xaddress> <name>");
  }
  const fn = resolveFunction(store, ref, binary);
  // The proposing agent's name, so its work can be told apart (and measured) among parallel agents.
  const hypothesis = proposeName(store, fn.id, name, agent ?? "agent");
  return { data: { hypothesis }, text: `${hypothesis.id}: ${fn.id} named ${name}` };
}

export async function runScoreNames(
  store: GraphStore,
  args: string[],
  truth: string | undefined,
  binary: string | undefined,
): Promise<Output> {
  const [what, ...extra] = args;
  if (what !== "names" || extra.length > 0 || truth === undefined) {
    throw new CliError("usage", "usage: atlas score names --truth <unstripped file> [--binary <bin_>]");
  }
  const binaries = store.nodesOfKind("binary").filter((b) => binary === undefined || b.id === binary);
  if (binaries.length !== 1) {
    throw new CliError(
      "usage",
      binaries.length === 0 ? `no binary ${binary ?? ""}` : "several binaries: name one with --binary",
    );
  }
  const score = await scoreNames(store, (binaries[0] as { id: string }).id, truth);
  return {
    data: score,
    text:
      `${score.keyed} functions in the key (${score.free} already named in the binary); ${score.proposed} names ` +
      `proposed: ${score.verified} right, ${score.rejected} wrong, ${score.inconclusive} not in the key; ` +
      `accuracy ${(score.accuracy * 100).toFixed(1)}% of the functions to name`,
  };
}
