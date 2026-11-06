// Replays every behaviour recorded for a program against a reconstruction of it (atlas lift --link's program, a
// rebuilt source tree...): the replay check. A scenario the reconstruction reproduces exactly (standard output and
// error, exit, output files) becomes verified; one it does not stays observed, with where the two differ. The
// verification names the reconstruction by its SHA-256, so a later build is checked again rather than assumed.
// Runs the reconstruction natively: the caller asked for it.
import type { GraphStore, Hypothesis } from "../graph/index.js";
import { differences, runScenario } from "../verify/replay/run-scenario.js";
import { fileSha256 } from "./file-hash.js";
import { NotFoundError } from "./function-context.js";
import { binaryId } from "./load-binary.js";
import type { BehaviourValue } from "./record-behaviour.js";

export interface ReplayResult {
  hypothesis: string;
  argv: string[];
  result: "pass" | "fail";
  differences: string[];
}

export async function replayBehaviour(
  store: GraphStore,
  original: string,
  reconstruction: string,
): Promise<{ binary: string; reconstruction: string; results: ReplayResult[] }> {
  const binary = binaryId(await fileSha256(original));
  if (store.getNode(binary) === undefined) throw new NotFoundError(`${original} is not loaded; atlas load it first`);
  const behaviours = store.hypothesesFor(binary, "behaviour").filter((h) => h.confidence !== "rejected");
  if (behaviours.length === 0) {
    throw new NotFoundError(`no behaviour recorded for ${original}; atlas record behaviour it first`);
  }
  const sha = await fileSha256(reconstruction);
  const results: ReplayResult[] = [];
  for (const h of behaviours) {
    const value = h.value as BehaviourValue;
    const got = await runScenario(reconstruction, value.scenario);
    const found = differences(value.expected, got);
    const pass = found.length === 0;
    const updated: Hypothesis = store.recordVerification(h.id, {
      confidence: pass ? "verified" : "observed",
      verification: {
        check: "replay",
        result: pass ? "pass" : "fail",
        details: `reconstruction sha256 ${sha}: ${pass ? "the same outcome" : found.join("; ")}`,
      },
    });
    results.push({
      hypothesis: updated.id,
      argv: value.scenario.argv,
      result: pass ? "pass" : "fail",
      differences: found,
    });
  }
  return { binary, reconstruction: sha, results };
}
