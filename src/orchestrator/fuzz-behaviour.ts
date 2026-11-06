// Differential testing of a reconstruction against its original: atlas fuzz behaviour. The recorded behaviours are
// the seeds; each round mutates one's inputs (standard input, input files: mutate-scenario.ts, seeded, so a run can
// be repeated), runs the original as the oracle and the reconstruction on the mutant, and when the original does
// the same twice but the reconstruction does otherwise, records the mutant as a new behaviour of the original
// (observed, author "fuzzer"): a failing acceptance test found without writing it, ready for atlas blame behaviour.
// Mutants the original does not repeat are counted and dropped. Runs both programs natively: the caller asked for it.
import type { GraphStore } from "../graph/index.js";
import { generator, mutateScenario } from "../verify/replay/mutate-scenario.js";
import { differences, forReconstruction, runScenario, type Scenario } from "../verify/replay/run-scenario.js";
import { fileSha256 } from "./file-hash.js";
import { NotFoundError } from "./function-context.js";
import { binaryId } from "./load-binary.js";
import { recordBehaviour, type BehaviourValue } from "./record-behaviour.js";

export interface FuzzResult {
  rounds: number;
  /** Mutants the original did not answer the same way twice: not usable as tests. */
  unstable: number;
  /** Mutants on which the reconstruction differs from the original, each recorded as a behaviour. */
  found: { hypothesis: string; differences: string[] }[];
}

export async function fuzzBehaviour(
  store: GraphStore,
  original: string,
  reconstruction: string,
  options: { rounds?: number; seed?: number; limit?: number } = {},
): Promise<FuzzResult> {
  const binary = binaryId(await fileSha256(original));
  if (store.getNode(binary) === undefined) throw new NotFoundError(`${original} is not loaded; atlas load it first`);
  const seeds = store
    .hypothesesFor(binary, "behaviour")
    .filter((h) => h.confidence !== "rejected")
    .map((h) => (h.value as BehaviourValue).scenario)
    .filter((s) => s.stdin !== undefined || (s.inputs?.length ?? 0) > 0);
  if (seeds.length === 0) {
    throw new NotFoundError(
      `no behaviour of ${original} has a standard input or input file to mutate; atlas record behaviour one first`,
    );
  }
  const random = generator(options.seed ?? 1);
  const rounds = options.rounds ?? 50;
  const limit = options.limit ?? 10;
  const result: FuzzResult = { rounds: 0, unstable: 0, found: [] };
  for (let round = 0; round < rounds && result.found.length < limit; round++) {
    result.rounds++;
    const mutant = mutateScenario(seeds[round % seeds.length] as Scenario, random) as Scenario;
    const expected = await runScenario(original, mutant);
    if (differences(expected, await runScenario(original, mutant), mutant.vary).length > 0) {
      result.unstable++;
      continue;
    }
    const found = differences(expected, await runScenario(reconstruction, forReconstruction(mutant)), mutant.vary);
    if (found.length === 0) continue;
    const { hypothesis } = await recordBehaviour(store, original, mutant, "fuzzer");
    result.found.push({ hypothesis: hypothesis.id, differences: found });
  }
  return result;
}
