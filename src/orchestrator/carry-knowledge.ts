// Knowledge carried over from a documented graph (M7): another Atlas graph of a related binary (an earlier version, a
// build with symbols, an open-source library) whose functions have names or verified rewrites. Each function of the
// target is matched to its most similar function there by fingerprint (function-fingerprint.ts); a clear match
// brings over a match hypothesis, the name (inferred) and the verified rewrite (proposed, then checked by the
// recompile check like any other: a rewrite that does not reproduce this build simply fails verification).
import type { GraphNode, GraphStore, Hypothesis } from "../graph/index.js";
import type { Architecture } from "../tools/engine-analysis.js";
import { createHash } from "node:crypto";
import { fingerprint, jaccard } from "./function-fingerprint.js";
import { forEachConcurrently } from "./parallel.js";
import { proposeName } from "./propose-name.js";
import { proposeRewrite } from "./propose-rewrite.js";
import { isRewriteValue } from "../verify/recompile/rewrite-value.js";

/** Below this, two functions are not taken for the same one. Measured on Lua (docs/ROADMAP.md, M7). */
export const MIN_SIMILARITY = 0.2;
/** The best candidate must beat the second by this much, or the match is ambiguous and left out. */
export const MIN_MARGIN = 0.05;
/** Functions shorter than this have too few instructions to tell apart. */
export const MIN_SIZE = 24;

const ENGINE_LABEL = /^(FUN|thunk_FUN|LAB|SUB|fcn|sub)_[0-9a-f]+$/i;
const RANK: Record<Hypothesis["confidence"], number> = {
  rejected: -1,
  guessed: 0,
  inferred: 1,
  observed: 2,
  verified: 3,
};

export interface CarryOutcome {
  compared: number;
  matched: number;
  ambiguous: number;
  names: number;
  rewrites: number;
}

interface Documented {
  fn: GraphNode;
  name?: string;
  rewrite?: Hypothesis;
}

function knowledge(source: GraphStore, fn: GraphNode): Documented {
  const best = (kind: Hypothesis["kind"]) =>
    source
      .hypothesesFor(fn.id, kind)
      .filter((h) => h.confidence !== "rejected")
      .sort((a, b) => RANK[b.confidence] - RANK[a.confidence])[0];
  const named = best("name");
  const label = fn.label !== undefined && !ENGINE_LABEL.test(fn.label) ? fn.label : undefined;
  const name = typeof named?.value === "string" ? named.value : label;
  const rewrite = best("rewrite");
  return {
    fn,
    ...(name !== undefined ? { name } : {}),
    ...(rewrite?.confidence === "verified" ? { rewrite } : {}),
  };
}

async function fingerprints(functions: GraphNode[], architecture: Architecture): Promise<Map<string, Set<string>>> {
  const out = new Map<string, Set<string>>();
  await forEachConcurrently(functions, async (f) => {
    const code = Buffer.from(f.code as string, "hex").subarray(0, f.size ?? 0);
    out.set(f.id, await fingerprint(code, architecture, f.address as string));
  });
  return out;
}

function candidates(store: GraphStore, binary: string): GraphNode[] {
  return store
    .nodesOfKind("function")
    .filter(
      (f) =>
        f.binary === binary &&
        f.code !== undefined &&
        f.address !== undefined &&
        (f.size ?? 0) >= MIN_SIZE &&
        f.thunk !== true &&
        f.generated === undefined,
    );
}

export async function carryKnowledge(
  store: GraphStore,
  binary: string,
  source: GraphStore,
  sourceBinary: string,
): Promise<CarryOutcome> {
  const architecture = store.getNode(binary)?.architecture;
  if (architecture === undefined) throw new Error(`${binary} has no recorded architecture`);
  if (source.getNode(sourceBinary)?.architecture !== architecture) {
    throw new Error(`the documented binary is not ${architecture}: fingerprints only compare one architecture`);
  }
  const documented = candidates(source, sourceBinary)
    .map((f) => knowledge(source, f))
    .filter((d) => d.name !== undefined || d.rewrite !== undefined);
  const targets = candidates(store, binary);
  const [mine, theirs] = await Promise.all([
    fingerprints(targets, architecture),
    fingerprints(
      documented.map((d) => d.fn),
      architecture,
    ),
  ]);
  // Inverted index: shingle to the documented functions that have it, so each target is compared only with
  // functions sharing at least one shingle.
  const index = new Map<string, number[]>();
  documented.forEach((d, i) => {
    for (const s of theirs.get(d.fn.id) ?? []) {
      const list = index.get(s) ?? [];
      list.push(i);
      index.set(s, list);
    }
  });
  const outcome: CarryOutcome = { compared: targets.length, matched: 0, ambiguous: 0, names: 0, rewrites: 0 };
  store.transaction(() => {
    for (const t of targets) {
      const prints = mine.get(t.id) ?? new Set<string>();
      const near = new Set<number>();
      for (const s of prints) for (const i of index.get(s) ?? []) near.add(i);
      const scored = [...near]
        .map((i) => ({
          d: documented[i] as Documented,
          score: jaccard(prints, theirs.get(documented[i]?.fn.id ?? "") ?? new Set()),
        }))
        .sort((a, b) => b.score - a.score);
      const [best, second] = scored;
      if (best === undefined || best.score < MIN_SIMILARITY) continue;
      if (second !== undefined && best.score - second.score < MIN_MARGIN) {
        outcome.ambiguous++;
        continue;
      }
      outcome.matched++;
      const value = { graph_function: best.d.fn.id, similarity: Number(best.score.toFixed(3)) };
      const id = `hyp_${createHash("sha256")
        .update(`${t.id}\nmatch\n${JSON.stringify(value)}`)
        .digest("hex")
        .slice(0, 32)}`;
      if (store.getHypothesis(id) === undefined) {
        store.proposeHypothesis({
          schema_version: 1,
          id,
          node: t.id,
          kind: "match",
          value: { ...value, ...(best.d.name !== undefined ? { name: best.d.name } : {}) },
          confidence: "inferred",
          evidence: [t.id],
          author: { agent: "matcher/fingerprint" },
        });
      }
      if (best.d.name !== undefined && /^[A-Za-z_][\w.:$@]{0,255}$/.test(best.d.name)) {
        proposeName(store, t.id, best.d.name, "matcher/fingerprint");
        outcome.names++;
      }
      if (best.d.rewrite !== undefined && isRewriteValue(best.d.rewrite.value)) {
        proposeRewrite(store, t.id, best.d.rewrite.value, "matcher/fingerprint", "inferred");
        outcome.rewrites++;
      }
    }
  });
  return outcome;
}
