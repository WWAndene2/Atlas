// Verifies rewrites with the right toolchain: the one given, or else the one detected for each rewrite's binary.
// Shared by the CLI and the MCP server.
import type { GraphStore, Hypothesis } from "../graph/index.js";
import type { Toolchain } from "../verify/recompile/recompile-check.js";
import { verifyRewrite, type VerifyOutcome } from "../verify/recompile/verify-rewrite.js";
import { checkRewriteDifferential, checkRewriteEquivalence } from "./check-behaviour.js";
import { binaryToolchain } from "./detect-toolchain.js";
import { NotFoundError } from "./function-context.js";
import { forEachConcurrently } from "./parallel.js";

export class NoToolchainError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NoToolchainError";
  }
}

function toolchainFor(store: GraphStore, h: Hypothesis, given?: Toolchain): Toolchain {
  if (given !== undefined) return given;
  const binary = store.getNode(h.node)?.binary;
  const detected = binary === undefined ? undefined : binaryToolchain(store, binary);
  if (detected === undefined) {
    throw new NoToolchainError(`no toolchain for ${binary ?? h.node}: give one, or run atlas detect toolchain`);
  }
  return { cc: detected.cc, flags: detected.flags };
}

/**
 * A rewrite whose bytes differ can then be checked for the same behaviour (angr, opt-in): `equivalence` (symbolic
 * proof), `differential` (concrete inputs; run when equivalence is not asked for or is inconclusive).
 */
export async function verifyOne(
  store: GraphStore,
  id: string,
  given?: Toolchain,
  behaviour: { equivalence?: boolean; differential?: boolean } = {},
): Promise<VerifyOutcome & { equivalence?: string; differential?: string }> {
  const h = store.getHypothesis(id);
  if (h === undefined) throw new NotFoundError(`no hypothesis ${id}`);
  const toolchain = toolchainFor(store, h, given);
  const outcome = await verifyRewrite(store, id, toolchain);
  if (outcome.check.result === "pass" || outcome.check.reason !== "mismatch") return outcome;
  const result: VerifyOutcome & { equivalence?: string; differential?: string } = { ...outcome };
  if (behaviour.equivalence === true) {
    const answer = await checkRewriteEquivalence(store, outcome.hypothesis, toolchain);
    result.equivalence = `${answer.result}: ${answer.details}`;
    if (answer.result !== "inconclusive") behaviour = { ...behaviour, differential: false };
  }
  if (behaviour.differential === true) {
    const answer = await checkRewriteDifferential(store, store.getHypothesis(id) ?? outcome.hypothesis, toolchain);
    result.differential = `${answer.result}: ${answer.details}`;
  }
  return { ...result, hypothesis: store.getHypothesis(id) ?? outcome.hypothesis };
}

/** Every rewrite not checked yet, in parallel; a missing toolchain is reported before any work starts. */
export async function verifyPending(
  store: GraphStore,
  given?: Toolchain,
): Promise<{ checked: number; counts: Record<string, number> }> {
  const pending = (store.allRecords("hypotheses") as Hypothesis[]).filter(
    (h) => h.kind === "rewrite" && h.verification === undefined,
  );
  const toolchains = new Map(pending.map((h) => [h.id, toolchainFor(store, h, given)]));
  const counts: Record<string, number> = {};
  await forEachConcurrently(pending, async (h) => {
    const { check } = await verifyRewrite(store, h.id, toolchains.get(h.id) as Toolchain);
    const key = check.result === "pass" ? "verified" : check.reason;
    counts[key] = (counts[key] ?? 0) + 1;
  });
  return { checked: pending.length, counts };
}
