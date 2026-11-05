// atlas claim task rewrite --agent <name> [--released] [--lease <seconds>] [--binary <bin_>]
// atlas release task <fn_id> --agent <name> [--note "<what was found>"]
import type { GraphStore, TaskClaims } from "../../graph/index.js";
import { rewriteQueue } from "../../orchestrator/rewrite-queue.js";
import { rewriteTask } from "../../orchestrator/rewrite-task.js";
import { CliError, type Output } from "../output.js";

export async function runClaimTask(
  store: GraphStore,
  claims: TaskClaims,
  args: string[],
  options: { agent?: string; lease?: string; binary?: string; released?: boolean },
): Promise<Output> {
  const [what, kind, ...extra] = args;
  if (what !== "task" || kind !== "rewrite" || extra.length > 0 || options.agent === undefined) {
    throw new CliError(
      "usage",
      "usage: atlas claim task rewrite --agent <name> [--released] [--lease <seconds>] [--binary <bin_>]",
    );
  }
  const seconds = Number(options.lease ?? "1800");
  if (!Number.isFinite(seconds) || seconds <= 0) throw new CliError("usage", "--lease takes a number of seconds");
  const binaries = store.nodesOfKind("binary").filter((b) => options.binary === undefined || b.id === options.binary);
  if (binaries.length !== 1) {
    throw new CliError("usage", binaries.length === 0 ? "no binary" : "several binaries: name one with --binary");
  }
  const queue = rewriteQueue(store, (binaries[0] as { id: string }).id).map((q) => q.id);
  const claim = claims.claimFirst(queue, options.agent, seconds * 1000, Date.now(), options.released === true);
  if (claim === undefined) {
    return {
      data: { claim: null, open: queue.length },
      text: options.released === true ? "no released task left to claim" : "no open task left to claim",
    };
  }
  const task = await rewriteTask(store, store.getNode(claim.task) as never);
  const notes = claims.notes(claim.task);
  return {
    data: { claim, task, notes },
    text: [
      `${claim.agent} holds ${claim.task} until ${new Date(claim.expires).toISOString()}`,
      ...notes.map((n) => `note from ${n.agent}: ${n.note}`),
    ].join("\n"),
  };
}

export function runReleaseTask(
  claims: TaskClaims,
  args: string[],
  agent: string | undefined,
  note: string | undefined,
): Output {
  const [what, task, ...extra] = args;
  if (what !== "task" || task === undefined || extra.length > 0 || agent === undefined) {
    throw new CliError("usage", 'usage: atlas release task <fn_id> --agent <name> [--note "<what was found>"]');
  }
  const released = claims.release(task, agent, note);
  return { data: { released }, text: released ? `${task} released` : `${agent} held no claim on ${task}` };
}
