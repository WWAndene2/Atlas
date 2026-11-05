// Gives a task back, and closes it as an unknown when the strongest agents have all given it up. A task given back
// below the top level moves up a level (task-levels.ts); one given back at the top level has nowhere to go, so each
// such release counts against a retry budget. When as many different top-level agents as the budget have given it
// up, the function's rewrite is recorded as an unknown (AGENTS.md 1.4: unresolved means unknown) and leaves the
// queue, instead of staying open forever: in the adaptive benchmark run, the only Opus agent was handed its own two
// releases until it broke off by hand.
import type { GraphNode, GraphStore, TaskClaims } from "../graph/index.js";
import { NotFoundError } from "./function-context.js";
import { taskLevel, type Levels } from "./task-levels.js";

/** Different top-level agents that must give a task up before it becomes an unknown, unless set otherwise. */
export const DEFAULT_RETRY_BUDGET = 2;

/** The unknown recording that no rewrite of a function could be verified. */
export function unknownRewriteId(functionId: string): string {
  return `unk_rewrite_${functionId.replace(/^fn_/, "")}`;
}

export interface ReleaseOutcome {
  released: boolean;
  /** Different agents that gave the task up at the top level, when this release was one of them. */
  topReleases?: number;
  /** The unknown recorded when the budget ran out. */
  unknown?: string;
}

export function releaseTask(
  store: GraphStore,
  claims: TaskClaims,
  release: { task: string; agent: string; note?: string; levels?: Levels; budget?: number },
): ReleaseOutcome {
  const fn = store.getNode(release.task);
  if (fn?.kind !== "function") throw new NotFoundError(`no function ${release.task}`);
  // Without levels every agent is at the top: there is no one stronger to hand the task to.
  const levels = release.levels ?? { of: 1, bounds: [] };
  const atTop = taskLevel(fn.size ?? 0, claims.releases(release.task), levels) === levels.of - 1;
  const released = claims.release(release.task, release.agent, release.note);
  if (!released || !atTop) return { released };
  const topReleases = claims.recordTopRelease(release.task, release.agent);
  if (topReleases < (release.budget ?? DEFAULT_RETRY_BUDGET)) return { released, topReleases };
  return { released, topReleases, unknown: recordUnknownRewrite(store, fn, topReleases) };
}

function recordUnknownRewrite(store: GraphStore, fn: GraphNode, agents: number): string {
  const id = unknownRewriteId(fn.id);
  if (store.getNode(id) === undefined) {
    store.putNode({
      schema_version: 1,
      id,
      kind: "unknown",
      ...(fn.binary !== undefined ? { binary: fn.binary } : {}),
      ...(fn.address !== undefined ? { address: fn.address } : {}),
      label: `rewrite of ${fn.id}: no rewrite verified; given up by ${agents} agents at the top level (their notes are kept with its claims)`,
    });
  }
  return id;
}
