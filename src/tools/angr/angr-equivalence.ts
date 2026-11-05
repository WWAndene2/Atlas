// Runs the symbolic equivalence check (equivalence.py, angr and Z3) on two machine-code versions of a function. angr
// lives in the Python environment scripts/setup.sh creates in the tools directory. x86-64 only for now.
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { repositoryPath } from "../../graph/index.js";
import { toolsDir } from "../tools-dir.js";

const run = promisify(execFile);

export interface CodeVersion {
  code: Uint8Array;
  address: number;
}

export interface EquivalenceAnswer {
  result: "equivalent" | "different" | "inconclusive";
  details: string;
  /** Argument values under which the versions differ. */
  counterexample?: Record<string, string>;
}

export class AngrUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AngrUnavailableError";
  }
}

/** The Python interpreter of the environment holding angr, checked to exist. */
export function locateAngr(env: NodeJS.ProcessEnv = process.env): string {
  const python = join(toolsDir(env), "py", "bin", "python");
  if (!existsSync(python)) throw new AngrUnavailableError(`no angr environment at ${python}; run scripts/setup.sh`);
  return python;
}

export async function checkEquivalence(
  python: string,
  original: CodeVersion,
  candidate: CodeVersion,
  options: { maxSteps?: number; buffer?: number; timeoutMs?: number } = {},
): Promise<EquivalenceAnswer> {
  const work = await mkdtemp(join(tmpdir(), "atlas-angr-"));
  try {
    const request = join(work, "request.json");
    await writeFile(
      request,
      JSON.stringify({
        original: { code: Buffer.from(original.code).toString("hex"), address: original.address },
        candidate: { code: Buffer.from(candidate.code).toString("hex"), address: candidate.address },
        max_steps: options.maxSteps ?? 300,
        buffer: options.buffer ?? 256,
      }),
    );
    let stdout: string;
    try {
      ({ stdout } = await run(python, [repositoryPath("src", "tools", "angr", "equivalence.py"), request], {
        timeout: options.timeoutMs ?? 120_000,
        maxBuffer: 16 * 1024 * 1024,
      }));
    } catch (error) {
      // A crash or a timeout proves nothing either way.
      return {
        result: "inconclusive",
        details: `angr did not finish: ${(error as Error).message.split("\n")[0] ?? ""}`,
      };
    }
    const line = stdout.trim().split("\n").pop() ?? "";
    const answer = JSON.parse(line) as EquivalenceAnswer;
    if (!["equivalent", "different", "inconclusive"].includes(answer.result)) {
      return { result: "inconclusive", details: "angr gave no answer" };
    }
    return answer;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
