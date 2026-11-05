// atlas repair rewrite <hyp_id|all> [--cc <compiler> --cflags="<flags>"]
import type { GraphStore } from "../../graph/index.js";
import { NotFoundError } from "../../orchestrator/function-context.js";
import { repairCandidates, repairRewrite, type RepairOutcome } from "../../orchestrator/repair-rewrite.js";
import { NoToolchainError, toolchainFor } from "../../orchestrator/verify-rewrites.js";
import { CliError, type Output } from "../output.js";

export async function runRepair(
  store: GraphStore,
  args: string[],
  options: { cc?: string; cflags?: string; binary?: string },
): Promise<Output> {
  const [what, id, ...extra] = args;
  if (what !== "rewrite" || id === undefined || extra.length > 0) {
    throw new CliError("usage", 'usage: atlas repair rewrite <hyp_id|all> [--cc <compiler> --cflags="<flags>"]');
  }
  const flags = (options.cflags ?? "").split(/\s+/).filter((f) => f !== "");
  const given = options.cc !== undefined ? { cc: options.cc, flags } : undefined;
  const ids = id === "all" ? repairCandidates(store, options.binary) : [id];
  const outcomes: RepairOutcome[] = [];
  try {
    for (const h of ids) {
      const hypothesis = store.getHypothesis(h);
      if (hypothesis === undefined) throw new NotFoundError(`no hypothesis ${h}`);
      outcomes.push(await repairRewrite(store, h, toolchainFor(store, hypothesis, given)));
    }
  } catch (error) {
    if (error instanceof NoToolchainError) throw new CliError("usage", error.message);
    if (error instanceof NotFoundError) throw new CliError("not_found", error.message);
    throw error;
  }
  const count = (r: RepairOutcome["result"]) => outcomes.filter((o) => o.result === r).length;
  const text =
    id === "all"
      ? `${outcomes.length} near misses: ${count("verified")} verified, ${count("improved")} closer, ${count("unchanged")} unchanged, ${count("skipped")} skipped`
      : outcomes
          .map(
            (o) =>
              `${o.hypothesis}: ${o.result} (${o.before ?? "?"} -> ${o.after ?? "?"} bytes differing, ${o.compiles} compiles${o.edits.length > 0 ? `; ${o.edits.join("; ")}` : ""}${o.reason !== undefined ? `; ${o.reason}` : ""})`,
          )
          .join("\n");
  return { data: { outcomes }, text };
}
