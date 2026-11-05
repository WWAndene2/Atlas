// When a rewrite compiles to different bytes than the original, it may still behave the same: a recompiled program
// only needs the same behaviour. Two checks through angr (src/tools/angr/), recorded through the verification path:
// symbolic equivalence (check "structural": proof, so verified) and the differential test on concrete inputs (check
// "differential": observed, not proof). A difference records the input that shows it; inconclusive changes nothing.
// x86-64 for now. Callees are opaque: the rewrite's calls are linked to the original's (link-calls.ts), and both
// versions must make the same calls with the same arguments; what a callee writes to memory is not modelled.
import type { GraphStore, Hypothesis } from "../graph/index.js";
import {
  checkEquivalence,
  locateAngr,
  runDifferential,
  type CodeVersion,
  type DifferentialAnswer,
  type EquivalenceAnswer,
} from "../tools/angr/index.js";
import { ghidraPreludeFlags } from "../verify/recompile/ghidra-prelude.js";
import { linkCalls } from "./link-calls.js";
import { recompileCheck, type Toolchain } from "../verify/recompile/recompile-check.js";
import { isRewriteValue } from "../verify/recompile/rewrite-value.js";

type Versions =
  { original: CodeVersion; candidate: CodeVersion; arity: Record<string, number | null> } | { inconclusive: string };

/** Where the candidate is placed: within reach of a 32-bit relative call from the original's callees. */
const CANDIDATE_ADDRESS = 0x40000000;

/** The original's machine code and the rewrite's, compiled; or why they cannot be set side by side. */
async function rewriteVersions(store: GraphStore, hypothesis: Hypothesis, toolchain: Toolchain): Promise<Versions> {
  const fn = store.getNode(hypothesis.node);
  const binary = fn?.binary === undefined ? undefined : store.getNode(fn.binary);
  if (!isRewriteValue(hypothesis.value) || fn?.code === undefined || fn.address === undefined) {
    return { inconclusive: "not a rewrite of a function with code" };
  }
  if (binary?.architecture !== "x86_64") return { inconclusive: "x86-64 only for now" };
  if (hypothesis.value.last !== undefined) return { inconclusive: "runs of functions are not compared" };
  const value = hypothesis.value;
  const check = await recompileCheck({
    source: value.source,
    name: value.name,
    original: Buffer.from(fn.code, "hex"),
    minimumSize: fn.size ?? 0,
    toolchain: {
      cc: toolchain.cc,
      flags: value.prelude === "ghidra" ? [...toolchain.flags, ...ghidraPreludeFlags()] : toolchain.flags,
    },
  });
  if (check.result === "pass") return { inconclusive: "identical bytes: nothing to compare" };
  if (check.reason !== "mismatch") return { inconclusive: `the rewrite does not compile: ${check.reason}` };
  const linked = linkCalls(
    store,
    fn.binary as string,
    check.compiled,
    check.relocations,
    CANDIDATE_ADDRESS,
    value.source,
  );
  if (linked.unresolved.length > 0) {
    return { inconclusive: `the rewrite calls functions not found in the binary: ${linked.unresolved.join(", ")}` };
  }
  return {
    // The original up to its engine-measured size: the code window may run on into padding.
    original: {
      code: Buffer.from(fn.code, "hex").subarray(0, Math.max(fn.size ?? 0, 1)),
      address: Number(BigInt(fn.address)),
    },
    candidate: { code: linked.code, address: CANDIDATE_ADDRESS },
    arity: linked.arity,
  };
}

export async function checkRewriteEquivalence(
  store: GraphStore,
  hypothesis: Hypothesis,
  toolchain: Toolchain,
): Promise<EquivalenceAnswer> {
  const v = await rewriteVersions(store, hypothesis, toolchain);
  if ("inconclusive" in v) return { result: "inconclusive", details: v.inconclusive };
  const answer = await checkEquivalence(locateAngr(), v.original, v.candidate, { arity: v.arity });
  if (answer.result === "equivalent") {
    store.recordVerification(hypothesis.id, {
      confidence: "verified",
      verification: {
        check: "structural",
        result: "pass",
        details: `equivalent to the original by symbolic execution: ${answer.details}`,
      },
    });
  } else if (answer.result === "different") {
    store.recordVerification(hypothesis.id, {
      confidence: hypothesis.confidence === "verified" ? "inferred" : hypothesis.confidence,
      verification: {
        check: "structural",
        result: "fail",
        details: `not equivalent: results differ for ${JSON.stringify(answer.counterexample ?? {})}`,
      },
    });
  }
  return answer;
}

/**
 * Runs the original and the rewrite on the same generated inputs. Same results raise the rewrite to observed (seen
 * to behave the same, not proven); different results record the input that shows it.
 */
export async function checkRewriteDifferential(
  store: GraphStore,
  hypothesis: Hypothesis,
  toolchain: Toolchain,
): Promise<DifferentialAnswer> {
  const v = await rewriteVersions(store, hypothesis, toolchain);
  if ("inconclusive" in v) return { result: "inconclusive", details: v.inconclusive };
  const answer = await runDifferential(locateAngr(), v.original, v.candidate, { arity: v.arity });
  if (answer.result !== "inconclusive") {
    const same = answer.result === "same";
    store.recordVerification(hypothesis.id, {
      confidence: same
        ? hypothesis.confidence === "verified"
          ? "verified"
          : "observed"
        : hypothesis.confidence === "verified"
          ? "inferred"
          : hypothesis.confidence,
      verification: {
        check: "differential",
        result: same ? "pass" : "fail",
        details: same ? answer.details : `${answer.details} for ${JSON.stringify(answer.counterexample ?? {})}`,
      },
    });
  }
  return answer;
}
