// Verifies rewrites with the right toolchain: the one given, or else the one detected for each rewrite's binary.
// Shared by the CLI and the MCP server.
import type { GraphStore, Hypothesis } from "../graph/index.js";
import type { Toolchain } from "../verify/recompile/recompile-check.js";
import { verifyRewrite, type VerifyOutcome } from "../verify/recompile/verify-rewrite.js";
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

export async function verifyOne(store: GraphStore, id: string, given?: Toolchain): Promise<VerifyOutcome> {
  const h = store.getHypothesis(id);
  if (h === undefined) throw new NotFoundError(`no hypothesis ${id}`);
  return verifyRewrite(store, id, toolchainFor(store, h, given));
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
