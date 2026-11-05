// The rewrite repairer: before an agent spends tokens on a near miss, Atlas tries the usual fixes itself. From a
// rewrite that compiles to different bytes, it applies each single edit of rewrite-mutations.ts, recompiles, and
// keeps the one that leaves the fewest differing bytes; then again from there, until the code matches, no edit
// helps, or the compile budget is spent (hill climbing: each compile takes tens of milliseconds, an agent's attempt
// thousands of tokens). A better source is proposed as a new rewrite (author repairer/auto) and verified, so agents
// start from it; the edits made are recorded in its verification details.
import type { GraphStore, Hypothesis } from "../graph/index.js";
import { ghidraPreludeFlags } from "../verify/recompile/ghidra-prelude.js";
import { recompileCheck, type Toolchain } from "../verify/recompile/recompile-check.js";
import { isRewriteValue, type RewriteValue } from "../verify/recompile/rewrite-value.js";
import { verifyRewrite } from "../verify/recompile/verify-rewrite.js";
import { forEachConcurrently } from "./parallel.js";
import { proposeRewrite } from "./propose-rewrite.js";
import { mutationsFor } from "./rewrite-mutations.js";

export const DEFAULT_COMPILE_BUDGET = 150;

export interface RepairOutcome {
  hypothesis: string;
  result: "verified" | "improved" | "unchanged" | "skipped";
  /** Differing bytes before and after (Infinity: does not compile). */
  before?: number;
  after?: number;
  edits: string[];
  compiles: number;
  repaired?: string;
  reason?: string;
}

export async function repairRewrite(
  store: GraphStore,
  hypothesisId: string,
  toolchain: Toolchain,
  budget = DEFAULT_COMPILE_BUDGET,
): Promise<RepairOutcome> {
  const h = store.getHypothesis(hypothesisId);
  const skip = (reason: string): RepairOutcome => ({
    hypothesis: hypothesisId,
    result: "skipped",
    edits: [],
    compiles: 0,
    reason,
  });
  if (h === undefined || h.kind !== "rewrite" || !isRewriteValue(h.value)) return skip("not a C rewrite");
  if (h.value.last !== undefined) return skip("runs of functions are not repaired");
  const fn = store.getNode(h.node);
  if (fn?.code === undefined || fn.size === undefined) return skip("the function has no code");
  const value: RewriteValue = h.value;
  const flags = value.prelude === "ghidra" ? [...toolchain.flags, ...ghidraPreludeFlags()] : toolchain.flags;
  let compiles = 0;
  const score = async (source: string): Promise<number> => {
    compiles++;
    const check = await recompileCheck({
      source,
      name: value.name,
      original: Buffer.from(fn.code as string, "hex"),
      minimumSize: fn.size as number,
      toolchain: { cc: toolchain.cc, flags },
    });
    if (check.result === "pass") return 0;
    return check.reason === "mismatch" ? check.differing : Infinity;
  };
  const before = await score(value.source);
  if (before === 0) return { hypothesis: hypothesisId, result: "verified", before, after: 0, edits: [], compiles };
  if (before === Infinity) return { ...skip("the rewrite does not compile"), compiles };
  let current = value.source;
  let best = before;
  const edits: string[] = [];
  while (best > 0 && compiles < budget) {
    const candidates = mutationsFor(current, value.name)
      .map((m) => ({ label: m.label, source: m.apply(current) }))
      .filter((c): c is { label: string; source: string } => c.source !== undefined)
      .slice(0, Math.max(0, budget - compiles));
    if (candidates.length === 0) break;
    const scored: { label: string; source: string; score: number }[] = [];
    await forEachConcurrently(candidates, async (c) => {
      scored.push({ ...c, score: await score(c.source) });
    });
    // Ties broken by the mutation order, so a run is repeatable.
    const top = scored.sort(
      (a, b) =>
        a.score - b.score ||
        candidates.findIndex((c) => c.label === a.label) - candidates.findIndex((c) => c.label === b.label),
    )[0];
    if (top === undefined || top.score >= best) break;
    current = top.source;
    best = top.score;
    edits.push(top.label);
  }
  if (best >= before)
    return { hypothesis: hypothesisId, result: "unchanged", before, after: before, edits: [], compiles };
  const repaired = proposeRewrite(store, h.node, { ...value, source: current }, "repairer/auto", "inferred");
  const { hypothesis } = await verifyRewrite(store, repaired.id, toolchain);
  store.recordVerification(hypothesis.id, {
    confidence: hypothesis.confidence,
    verification: {
      ...(hypothesis.verification as NonNullable<Hypothesis["verification"]>),
      details: `${hypothesis.verification?.details ?? ""} (repaired from ${hypothesisId}: ${edits.join("; ")})`,
    },
  });
  return {
    hypothesis: hypothesisId,
    result: best === 0 ? "verified" : "improved",
    before,
    after: best,
    edits,
    compiles,
    repaired: repaired.id,
  };
}

/** For each function without a verified rewrite, its closest rewrite that compiles to different bytes. */
export function repairCandidates(store: GraphStore, binary?: string): string[] {
  const out: string[] = [];
  for (const fn of store.nodesOfKind("function")) {
    if (binary !== undefined && fn.binary !== binary) continue;
    const rewrites = store.hypothesesFor(fn.id, "rewrite");
    if (rewrites.some((r) => r.confidence === "verified")) continue;
    const near = rewrites
      .map((r) => ({ r, n: Number(/^(\d+) bytes differ/.exec(r.verification?.details ?? "")?.[1] ?? NaN) }))
      .filter((x) => Number.isFinite(x.n))
      .sort((a, b) => a.n - b.n)[0];
    if (near !== undefined) out.push(near.r.id);
  }
  return out;
}
