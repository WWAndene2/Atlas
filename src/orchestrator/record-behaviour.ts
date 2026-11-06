// Records a behaviour of a loaded program: runs the original on a scenario (its arguments, standard input,
// environment and input files) and keeps what it did (standard output and error, exit, the output files named) as a
// behaviour hypothesis on the binary, observed, with a capture evidence. The program runs twice: a scenario whose
// outcome differs between the two runs (a clock, a random number, an address) is refused, since no reconstruction
// could be held to it. These are the acceptance tests of the whole program: atlas verify behaviour replays them.
// Runs the target natively: the caller asked for it.
import { createHash } from "node:crypto";
import type { GraphStore, Hypothesis } from "../graph/index.js";
import { differences, runScenario, type Outcome, type Scenario } from "../verify/replay/run-scenario.js";
import { fileSha256 } from "./file-hash.js";
import { NotFoundError } from "./function-context.js";
import { binaryId } from "./load-binary.js";

export interface BehaviourValue {
  scenario: Scenario;
  expected: Outcome;
}

export class UnstableBehaviourError extends Error {}

export async function recordBehaviour(
  store: GraphStore,
  program: string,
  scenario: Scenario,
  agent = "recorder",
  now = new Date(),
): Promise<{ hypothesis: Hypothesis; created: boolean }> {
  const binary = binaryId(await fileSha256(program));
  if (store.getNode(binary) === undefined) throw new NotFoundError(`${program} is not loaded; atlas load it first`);
  const first = await runScenario(program, scenario);
  const second = await runScenario(program, scenario);
  const unstable = differences(first, second);
  if (unstable.length > 0) {
    throw new UnstableBehaviourError(`the program does not do the same twice on this scenario: ${unstable.join("; ")}`);
  }
  const value: BehaviourValue = { scenario, expected: first };
  const digest = createHash("sha256")
    .update(`${binary}\nbehaviour\n${JSON.stringify(value)}`)
    .digest("hex");
  const id = `hyp_${digest.slice(0, 32)}`;
  const existing = store.getHypothesis(id);
  if (existing !== undefined) return { hypothesis: existing, created: false };
  const evidence = `evd_${digest.slice(32, 64)}`;
  store.putEvidence({
    schema_version: 1,
    id: evidence,
    source: "capture",
    summary:
      `two runs of ${binary} with arguments ${JSON.stringify(scenario.argv)}` +
      `${scenario.stdin !== undefined ? " and a standard input" : ""}: exit ${String(first.exit)}, the same both times`,
    limitations: [
      "one scenario: what the program does on other inputs is not covered",
      "run in a fresh directory with a fixed environment (argv[0] 'program', LC_ALL=C, TZ=UTC)",
    ],
    created_at: now.toISOString(),
  });
  const hypothesis: Hypothesis = {
    schema_version: 1,
    id,
    node: binary,
    kind: "behaviour",
    value,
    confidence: "observed",
    evidence: [evidence],
    author: { agent },
  };
  store.proposeHypothesis(hypothesis);
  return { hypothesis, created: true };
}
