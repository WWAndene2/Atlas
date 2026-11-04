// Adds a rewrite hypothesis (a function's C) to the graph: Ghidra's decompilation, or an agent's improved source.
// The ID derives from the function and the source, so proposing the same source twice keeps one hypothesis.
import { createHash } from "node:crypto";
import type { GraphStore, Hypothesis } from "../graph/index.js";
import { isRewriteValue, type RewriteValue } from "../verify/recompile/rewrite-value.js";
import { NotFoundError } from "./function-context.js";

export function proposeRewrite(
  store: GraphStore,
  functionId: string,
  value: RewriteValue,
  author: string,
  confidence: "guessed" | "inferred" = "guessed",
): Hypothesis {
  if (store.getNode(functionId)?.kind !== "function") throw new NotFoundError(`no function ${functionId}`);
  if (!isRewriteValue(value)) throw new Error("a rewrite needs language c, a source and the function's name in it");
  const id = `hyp_${createHash("sha256")
    .update(`${functionId}\nrewrite\n${JSON.stringify(value)}`)
    .digest("hex")
    .slice(0, 32)}`;
  const existing = store.getHypothesis(id);
  if (existing !== undefined) return existing;
  const hypothesis: Hypothesis = {
    schema_version: 1,
    id,
    node: functionId,
    kind: "rewrite",
    value,
    confidence,
    // The function node is the evidence: its code is what the source claims to reproduce.
    evidence: [functionId],
    author: { agent: author },
  };
  store.proposeHypothesis(hypothesis);
  return hypothesis;
}
