// Behaviours carried from one build of a program to another: atlas copy behaviour. A program built from the same
// sources for another platform (Lua for Linux, Windows, Android) should do the same on the same scenario, so the
// behaviours recorded on a build that runs here become the acceptance tests of one that does not (no emulator for
// its CPU, no Windows). Each is copied onto the target binary at inferred, not observed (it was not seen on that
// binary), with the source behaviour's capture and the reference binary as evidence and the source named;
// replaying it on the target's reconstruction (atlas verify behaviour) is then what checks it. A behaviour already
// copied is not copied again.
import { createHash } from "node:crypto";
import type { GraphStore, Hypothesis } from "../graph/index.js";
import { fileSha256 } from "./file-hash.js";
import { NotFoundError } from "./function-context.js";
import { binaryId } from "./load-binary.js";

export async function copyBehaviour(
  store: GraphStore,
  reference: string,
  target: string,
): Promise<{ copied: string[]; already: number }> {
  const from = binaryId(await fileSha256(reference));
  const to = binaryId(await fileSha256(target));
  for (const [path, id] of [
    [reference, from],
    [target, to],
  ] as const) {
    if (store.getNode(id) === undefined) throw new NotFoundError(`${path} is not loaded; atlas load it first`);
  }
  if (from === to) throw new Error("the reference and the target are the same binary");
  const behaviours = store.hypothesesFor(from, "behaviour").filter((h) => h.confidence !== "rejected");
  if (behaviours.length === 0) throw new NotFoundError(`no behaviour recorded for ${reference}`);
  const copied: string[] = [];
  let already = 0;
  store.transaction(() => {
    for (const h of behaviours) {
      const id = `hyp_${createHash("sha256").update(`${to}\nbehaviour\ncopied\n${h.id}`).digest("hex").slice(0, 32)}`;
      if (store.getHypothesis(id) !== undefined) {
        already++;
        continue;
      }
      const copy: Hypothesis = {
        schema_version: 1,
        id,
        node: to,
        kind: "behaviour",
        // The source behaviour's own capture and the reference binary are the evidence; the source is named.
        value: { ...(h.value as object), copied_from: h.id },
        confidence: "inferred",
        evidence: [...h.evidence, from],
        author: { agent: "copier" },
      };
      store.proposeHypothesis(copy);
      copied.push(id);
    }
  });
  return { copied, already };
}
