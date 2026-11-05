// Adds a name hypothesis to a function. The ID derives from the function and the name, so proposing the same name
// twice keeps one hypothesis; different names for one function coexist until verification settles them.
import { createHash } from "node:crypto";
import type { GraphStore, Hypothesis } from "../graph/index.js";
import { NotFoundError } from "./function-context.js";

export function proposeName(store: GraphStore, functionId: string, name: string, author: string): Hypothesis {
  if (store.getNode(functionId)?.kind !== "function") throw new NotFoundError(`no function ${functionId}`);
  if (!/^[A-Za-z_][\w.:$@]{0,255}$/.test(name)) throw new Error(`${JSON.stringify(name)} is not a function name`);
  const id = `hyp_${createHash("sha256").update(`${functionId}\nname\n${name}`).digest("hex").slice(0, 32)}`;
  const existing = store.getHypothesis(id);
  if (existing !== undefined) return existing;
  const hypothesis: Hypothesis = {
    schema_version: 1,
    id,
    node: functionId,
    kind: "name",
    value: name,
    confidence: "guessed",
    evidence: [functionId],
    author: { agent: author },
  };
  store.proposeHypothesis(hypothesis);
  return hypothesis;
}
