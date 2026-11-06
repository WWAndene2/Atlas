// The symbols check: a name hypothesis is compared with the answer key, the unstripped build's symbol table, and
// recorded verified when it matches, rejected otherwise. Only available on ground-truth targets (built from known
// sources), where it measures how well agents name functions (AGENTS.md 3.5).
//
// Names are compared after removing what compilers add and sources do not contain: leading underscores (a platform
// prefix on Windows and old Unix), and GCC's suffixes for specialised copies (.isra.0, .constprop.1, .part.0, .cold).
import type { GraphStore, Hypothesis } from "../../graph/index.js";

export function normaliseName(name: string): string {
  return name
    .replace(/^_+/, "")
    .replace(/(\.(isra|constprop|part|cold|lto_priv|localalias)(\.\d+)?)+$/, "")
    .toLowerCase();
}

export type NameVerdict = "verified" | "rejected" | "no_key";

/** Records the outcome of one name hypothesis against the true name at its function's address. */
export function checkName(store: GraphStore, hypothesis: Hypothesis, truth: string | undefined): NameVerdict {
  if (hypothesis.kind !== "name" || typeof hypothesis.value !== "string") {
    throw new Error(`${hypothesis.id} is not a name hypothesis`);
  }
  if (truth === undefined) {
    // No symbol at that address in the key: the name can be neither confirmed nor refuted.
    store.recordVerification(hypothesis.id, {
      confidence: hypothesis.confidence,
      verification: {
        check: "symbols",
        result: "inconclusive",
        details: "no symbol at this address in the answer key",
      },
    });
    return "no_key";
  }
  const pass = normaliseName(hypothesis.value) === normaliseName(truth);
  store.recordVerification(hypothesis.id, {
    confidence: pass ? "verified" : "rejected",
    verification: {
      check: "symbols",
      result: pass ? "pass" : "fail",
      details: pass ? `matches ${truth}` : `the symbol is ${truth}`,
    },
  });
  return pass ? "verified" : "rejected";
}
