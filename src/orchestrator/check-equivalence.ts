// When a rewrite compiles to different bytes than the original, it may still do the same thing: a recompiled program
// only needs the same behaviour. This asks angr (src/tools/angr/) whether the two machine codes are equivalent, and
// records the answer through the verification path (check "structural"): equivalent makes the rewrite verified,
// different records the counterexample, inconclusive changes nothing. x86-64 leaf functions only for now: the check
// models no callee, and loops must end within a bound (equivalence.py).
import type { GraphStore, Hypothesis } from "../graph/index.js";
import { checkEquivalence, locateAngr, type EquivalenceAnswer } from "../tools/angr/index.js";
import { ghidraPreludeFlags } from "../verify/recompile/ghidra-prelude.js";
import { recompileCheck, type Toolchain } from "../verify/recompile/recompile-check.js";
import { isRewriteValue } from "../verify/recompile/rewrite-value.js";

export async function checkRewriteEquivalence(
  store: GraphStore,
  hypothesis: Hypothesis,
  toolchain: Toolchain,
): Promise<EquivalenceAnswer> {
  const fn = store.getNode(hypothesis.node);
  const binary = fn?.binary === undefined ? undefined : store.getNode(fn.binary);
  if (!isRewriteValue(hypothesis.value) || fn?.code === undefined || fn.address === undefined) {
    return { result: "inconclusive", details: "not a rewrite of a function with code" };
  }
  if (binary?.architecture !== "x86_64") {
    return { result: "inconclusive", details: "the equivalence check covers x86-64 only for now" };
  }
  if (hypothesis.value.last !== undefined) {
    return { result: "inconclusive", details: "runs of functions are not checked for equivalence" };
  }
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
  if (check.result === "pass") return { result: "equivalent", details: "identical bytes" };
  if (check.reason !== "mismatch")
    return { result: "inconclusive", details: `the rewrite does not compile: ${check.reason}` };
  const answer = await checkEquivalence(
    locateAngr(),
    // The original up to its engine-measured size: the code window may run on into padding.
    { code: Buffer.from(fn.code, "hex").subarray(0, Math.max(fn.size ?? 0, 1)), address: Number(BigInt(fn.address)) },
    { code: check.compiled, address: 0x40000000 },
  );
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
