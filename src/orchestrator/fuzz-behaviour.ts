// Differential testing of a reconstruction against its original: atlas fuzz behaviour. The recorded behaviours are
// the seeds; each round mutates one's inputs (standard input, input files: mutate-scenario.ts, seeded, so a run can
// be repeated), runs the original as the oracle and the reconstruction on the mutant, and when the original does
// the same twice but the reconstruction does otherwise, records the mutant as a new behaviour of the original
// (observed, author "fuzzer"): a failing acceptance test found without writing it, ready for atlas blame behaviour.
// Mutants the original does not repeat are counted and dropped. Runs both programs natively: the caller asked for it.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { GraphStore } from "../graph/index.js";
import { readCoverage } from "../verify/replay/read-coverage.js";
import { generator, mutateScenario } from "../verify/replay/mutate-scenario.js";
import { differences, forReconstruction, runScenario, type Scenario } from "../verify/replay/run-scenario.js";
import { fileSha256 } from "./file-hash.js";
import { NotFoundError } from "./function-context.js";
import { binaryId } from "./load-binary.js";
import { recordBehaviour, UnstableBehaviourError, type BehaviourValue } from "./record-behaviour.js";

export interface FuzzResult {
  rounds: number;
  /** Mutants the original did not answer the same way twice: not usable as tests. */
  unstable: number;
  /** Mutants on which the reconstruction differs from the original, each recorded as a behaviour. */
  found: { hypothesis: string; differences: string[] }[];
  /** Functions the reconstruction reached over the run, when it reports coverage (ATLAS_COVERAGE). */
  covered?: number;
  /** Mutants kept as seeds because they reached functions no earlier run had. */
  seeded: number;
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
  const result: FuzzResult = { rounds: 0, unstable: 0, found: [], seeded: 0 };
  // The functions the reconstruction reached over the run, when it reports them (ATLAS_COVERAGE).
  const covered = new Set<string>();
  const work = await mkdtemp(join(tmpdir(), "atlas-fuzz-"));
  try {
    for (let round = 0; round < rounds && result.found.length < limit; round++) {
      result.rounds++;
      const mutant = mutateScenario(seeds[round % seeds.length] as Scenario, random) as Scenario;
      const expected = await runScenario(original, mutant);
      if (differences(expected, await runScenario(original, mutant), mutant.vary).length > 0) {
        result.unstable++;
        continue;
      }
      const file = join(work, "coverage.txt");
      await rm(file, { force: true });
      const got = await runScenario(reconstruction, forReconstruction(mutant), { ATLAS_COVERAGE: file });
      const reached = await readCoverage(file);
      // A mutant that reaches a function no earlier run reached becomes a seed itself: later rounds start from it.
      if (reached !== undefined && [...reached].some((a) => !covered.has(a))) {
        for (const a of reached) covered.add(a);
        seeds.push(mutant);
        result.seeded++;
      }
      const found = differences(expected, got, mutant.vary);
      if (found.length === 0) continue;
      // Recording runs the original more times than the oracle did: a mutant it then finds unstable (a random line
      // the two oracle runs agreed on) is counted as unstable, and the run goes on.
      try {
        const { hypothesis } = await recordBehaviour(store, original, mutant, "fuzzer");
        result.found.push({ hypothesis: hypothesis.id, differences: found });
      } catch (error) {
        if (!(error instanceof UnstableBehaviourError)) throw error;
        result.unstable++;
      }
    }
  } finally {
    await rm(work, { recursive: true, force: true });
  }
  if (covered.size > 0) result.covered = covered.size;
  return result;
}
