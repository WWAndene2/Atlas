// Verifies a rewrite hypothesis by recompiling it and comparing with the function's code in the graph, and records
// the outcome: verified when every byte outside relocations matches, otherwise the confidence it had, with the
// failure and its details, so the agent can fix the source and propose again.
import type { GraphStore, Hypothesis } from "../../graph/index.js";
import { repositoryPath } from "../../graph/index.js";
import { recompileCheck, type RecompileResult, type Toolchain } from "./recompile-check.js";
import { isRewriteValue } from "./rewrite-value.js";

export class VerifyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerifyError";
  }
}

export interface VerifyOutcome {
  hypothesis: Hypothesis;
  check: RecompileResult;
}

export async function verifyRewrite(
  store: GraphStore,
  hypothesisId: string,
  toolchain: Toolchain,
): Promise<VerifyOutcome> {
  const hypothesis = store.getHypothesis(hypothesisId);
  if (hypothesis === undefined) throw new VerifyError(`no hypothesis ${hypothesisId}`);
  if (hypothesis.kind !== "rewrite" || !isRewriteValue(hypothesis.value)) {
    throw new VerifyError(`${hypothesisId} is not a C rewrite`);
  }
  const fn = store.getNode(hypothesis.node);
  if (fn?.kind !== "function" || fn.code === undefined || fn.size === undefined) {
    throw new VerifyError(`${hypothesis.node} has no code to compare with; load its binary again`);
  }
  const value = hypothesis.value;
  const flags =
    value.prelude === "ghidra"
      ? [...toolchain.flags, "-include", repositoryPath("src", "verify", "recompile", "ghidra-types.h")]
      : toolchain.flags;
  const check = await recompileCheck({
    source: value.source,
    name: value.name,
    original: Buffer.from(fn.code, "hex"),
    minimumSize: fn.size,
    toolchain: { cc: toolchain.cc, flags },
  });
  const toolchainText = `${toolchain.cc} ${toolchain.flags.join(" ")}`.trim();
  const updated = store.recordVerification(hypothesisId, {
    confidence:
      check.result === "pass" ? "verified" : hypothesis.confidence === "verified" ? "inferred" : hypothesis.confidence,
    verification: {
      check: "recompile",
      result: check.result,
      details:
        check.result === "pass"
          ? `matches the original's ${check.size} bytes (${check.masked} under relocations) with ${toolchainText}`
          : check.reason === "mismatch"
            ? `${check.differing} bytes differ, first at offset ${check.firstDifference}; compiled ${check.size} bytes, original at least ${check.originalSize}, with ${toolchainText}`
            : `${check.reason}: ${check.details}`,
    },
  });
  return { hypothesis: updated, check };
}
