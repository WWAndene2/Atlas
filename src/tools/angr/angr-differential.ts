// Runs the differential test (differential.py): both machine-code versions of a function executed by angr on the
// same concrete inputs. "same" is evidence on the inputs run, not proof; "different" comes with the input.
import { runAngrScript, versions, type CodeVersion } from "./angr-equivalence.js";

export interface DifferentialAnswer {
  result: "same" | "different" | "inconclusive";
  details: string;
  counterexample?: Record<string, string>;
}

export async function runDifferential(
  python: string,
  original: CodeVersion,
  candidate: CodeVersion,
  options: { inputs?: number; maxSteps?: number; buffer?: number; seed?: number; timeoutMs?: number } = {},
): Promise<DifferentialAnswer> {
  return runAngrScript<DifferentialAnswer>(
    python,
    "differential.py",
    {
      ...versions(original, candidate),
      inputs: options.inputs ?? 100,
      max_steps: options.maxSteps ?? 2000,
      buffer: options.buffer ?? 256,
      seed: options.seed ?? 1,
    },
    ["same", "different", "inconclusive"],
    options.timeoutMs ?? 300_000,
  );
}
