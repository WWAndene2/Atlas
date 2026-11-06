// Scores the names proposed for a binary's functions against its answer key (the unstripped build), recording each
// outcome through the symbols check. Functions whose true name is already the engine's label (exported symbols left
// in a stripped binary) are free answers: counted apart, so the accuracy measures naming, not reading.
import type { GraphStore } from "../graph/index.js";
import { functionSymbols } from "../tools/symbols/index.js";
import { checkName, normaliseName } from "../verify/symbols/name-check.js";

export interface NameScore {
  /** Functions of the binary (not stubs) that the key names. */
  keyed: number;
  /** Of those, the ones whose label already is the true name. */
  free: number;
  /** Name hypotheses checked, and how they came out. */
  proposed: number;
  verified: number;
  rejected: number;
  inconclusive: number;
  /** Keyed functions, free ones excluded, that have a verified name: the share named correctly. */
  accuracy: number;
}

export async function scoreNames(store: GraphStore, binary: string, keyPath: string): Promise<NameScore> {
  const key = new Map((await functionSymbols(keyPath)).map((s) => [s.address, s.name]));
  const functions = store
    .nodesOfKind("function")
    .filter((n) => n.binary === binary && n.thunk !== true && n.address !== undefined);
  const score: NameScore = { keyed: 0, free: 0, proposed: 0, verified: 0, rejected: 0, inconclusive: 0, accuracy: 0 };
  const named = new Set<string>();
  store.transaction(() => {
    for (const fn of functions) {
      const truth = key.get(fn.address ?? "");
      const free = truth !== undefined && fn.label !== undefined && normaliseName(fn.label) === normaliseName(truth);
      if (truth !== undefined) score.keyed++;
      if (free) score.free++;
      for (const h of store.hypothesesFor(fn.id, "name")) {
        score.proposed++;
        const verdict = checkName(store, h, truth);
        if (verdict === "verified") {
          score.verified++;
          if (!free) named.add(fn.id);
        } else if (verdict === "rejected") score.rejected++;
        else score.inconclusive++;
      }
    }
  });
  const scorable = score.keyed - score.free;
  score.accuracy = scorable === 0 ? 0 : named.size / scorable;
  return score;
}
