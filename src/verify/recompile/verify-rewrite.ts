// Verifies a rewrite hypothesis by recompiling it and comparing with the function's code in the graph, and records
// the outcome: verified when every byte outside relocations matches, otherwise the confidence it had, with the
// failure and its details, so the agent can fix the source and propose again.
import type { GraphStore, Hypothesis } from "../../graph/index.js";
import { recompileCheck, type RecompileResult, type Toolchain } from "./recompile-check.js";
import { ghidraPreludeFlags } from "./ghidra-prelude.js";
import { isRewriteValue } from "./rewrite-value.js";

export class VerifyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerifyError";
  }
}

/**
 * The original bytes a rewrite is compared with: the function's code, or for a run, the code of every function of
 * the binary from the first's entry to the last's, which is contiguous since each function's code reaches the next.
 */
function referenceCode(store: GraphStore, first: string, last?: string): { bytes: Buffer; minimumSize: number } {
  const start = store.getNode(first);
  if (
    start?.kind !== "function" ||
    start.code === undefined ||
    start.size === undefined ||
    start.address === undefined
  ) {
    throw new VerifyError(`${first} has no code to compare with; load its binary again`);
  }
  if (last === undefined) return { bytes: Buffer.from(start.code, "hex"), minimumSize: start.size };
  const end = store.getNode(last);
  if (end?.kind !== "function" || end.binary !== start.binary || end.address === undefined || end.size === undefined) {
    throw new VerifyError(`${last} is not a function of the same binary as ${first}`);
  }
  const [from, to] = [BigInt(start.address), BigInt(end.address)];
  if (to < from) throw new VerifyError(`${last} comes before ${first}; a run goes forward`);
  const run = store
    .nodesOfKind("function")
    .filter(
      (n) =>
        n.binary === start.binary && n.address !== undefined && BigInt(n.address) >= from && BigInt(n.address) <= to,
    )
    .sort((a, b) => (BigInt(a.address ?? 0) < BigInt(b.address ?? 0) ? -1 : 1));
  let expected = from;
  for (const n of run) {
    if (n.code === undefined || BigInt(n.address ?? 0) !== expected) {
      throw new VerifyError(`the run from ${first} to ${last} has a gap at ${n.id}; load the binary again`);
    }
    expected += BigInt(n.code.length / 2);
  }
  return {
    bytes: Buffer.from(run.map((n) => n.code ?? "").join(""), "hex"),
    minimumSize: Number(to - from) + end.size,
  };
}

/** The function's address when its binary is x86-64 (where relocation targets are checked), else undefined. */
function addressChecked(store: GraphStore, node: string): number | undefined {
  const fn = store.getNode(node);
  const binary = fn?.binary === undefined ? undefined : store.getNode(fn.binary);
  return binary?.architecture === "x86_64" && fn?.address !== undefined ? Number(BigInt(fn.address)) : undefined;
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
  const value = hypothesis.value;
  const reference = referenceCode(store, hypothesis.node, value.last?.node);
  const flags = value.prelude === "ghidra" ? [...toolchain.flags, ...ghidraPreludeFlags()] : toolchain.flags;
  const address = addressChecked(store, hypothesis.node);
  const check = await recompileCheck({
    source: value.source,
    name: value.name,
    ...(value.last !== undefined ? { last: value.last.name } : {}),
    original: reference.bytes,
    minimumSize: reference.minimumSize,
    toolchain: { cc: toolchain.cc, flags },
    // x86-64: references by address (DAT_<hex>...) must point where the original's do.
    ...(address !== undefined ? { address } : {}),
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
