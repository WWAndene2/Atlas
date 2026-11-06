// Records a behaviour of a loaded program: runs the original on a scenario (its arguments, standard input,
// environment and input files) and keeps what it did (standard output and error, exit, the output files named) as a
// behaviour hypothesis on the binary, observed, with a capture evidence. The program runs twice: a scenario whose
// outcome differs between the two runs (a clock, a random number, an address) is refused, since no reconstruction
// could be held to it (it runs RECORDING_RUNS times, each compared with the first), unless the parts that vary
// are named (the scenario's vary patterns, masked in every comparison). The runs only catch what differs between
// them: a clock read within one second agrees. These are the acceptance tests of the whole program: atlas verify
// behaviour replays them.
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

/**
 * How many times the original runs before a scenario is recorded: each run after the first must agree with it.
 * Two runs let a coin-flip through half the time (Lua's constructs.lua prints a random 0 or 1); three, a quarter.
 */
export const RECORDING_RUNS = 3;

export class UnstableBehaviourError extends Error {}
export class InvalidScenarioError extends Error {}

export async function recordBehaviour(
  store: GraphStore,
  program: string,
  scenario: Scenario,
  agent = "recorder",
  now = new Date(),
  runs = RECORDING_RUNS,
): Promise<{ hypothesis: Hypothesis; created: boolean }> {
  const binary = binaryId(await fileSha256(program));
  if (store.getNode(binary) === undefined) throw new NotFoundError(`${program} is not loaded; atlas load it first`);
  for (const pattern of scenario.vary ?? []) {
    try {
      new RegExp(pattern, "g");
    } catch (error) {
      throw new InvalidScenarioError(`--vary ${pattern}: ${(error as Error).message}`);
    }
  }
  if (!Number.isInteger(runs) || runs < 2) throw new InvalidScenarioError(`runs ${runs}: at least 2`);
  const first = await runScenario(program, scenario);
  let unstable: string[] = [];
  for (let k = 1; k < runs && unstable.length === 0; k++) {
    unstable = differences(first, await runScenario(program, scenario), scenario.vary);
  }
  if (unstable.length > 0) {
    throw new UnstableBehaviourError(
      `the program does not do the same each time on this scenario: ${unstable.join("; ")} ` +
        "(a part that legitimately varies, such as a time, can be masked with a regular expression: --vary)",
    );
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
      `${runs} runs of ${binary} with arguments ${JSON.stringify(scenario.argv)}` +
      `${scenario.stdin !== undefined ? " and a standard input" : ""}: exit ${String(first.exit)}, the same each time`,
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
