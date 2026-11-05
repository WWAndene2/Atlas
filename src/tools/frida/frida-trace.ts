// Runs a native program under Frida (trace.py) and returns, per function address, how often it ran and what its
// argument registers held. Frida lives in the Python environment scripts/setup.sh creates in the tools directory,
// beside angr. This RUNS the target: callers make sure the operator asked for it.
import { execFile, execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { repositoryPath } from "../../graph/index.js";
import { toolsDir } from "../tools-dir.js";

const run = promisify(execFile);

export const FRIDA_VERSION = "17.25.2";

export class FridaUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FridaUnavailableError";
  }
}

export interface ArgumentObservation {
  pointer: number;
  integer: number;
  zero: number;
}

export interface FunctionTrace {
  calls: number;
  /** rdi, rsi, rdx, rcx, r8, r9 over the sampled calls; registers past the real arity hold leftovers. */
  args: ArgumentObservation[];
  returned: number;
  /** Sampled returns whose rax pointed into mapped memory. */
  result_pointer: number;
  /** Why Frida could not hook the function (too short, for instance). */
  error?: string;
}

export interface TraceResult {
  exit: "exited" | "timeout" | "detached";
  module_base: string;
  functions: Record<string, FunctionTrace>;
}

export function locateFrida(env: NodeJS.ProcessEnv = process.env): string {
  const python = join(toolsDir(env), "py", "bin", "python");
  const missing = new FridaUnavailableError(`no Frida in ${join(toolsDir(env), "py")}; run scripts/setup.sh`);
  if (!existsSync(python)) throw missing;
  try {
    execFileSync(python, ["-c", "import frida"], { stdio: "ignore" });
  } catch {
    throw missing;
  }
  return python;
}

export async function traceProgram(
  python: string,
  request: {
    program: string;
    argv: string[];
    stdin?: string;
    functions: number[];
    samples?: number;
    timeoutS?: number;
  },
): Promise<TraceResult> {
  const work = await mkdtemp(join(tmpdir(), "atlas-frida-"));
  try {
    const path = join(work, "request.json");
    const timeout = request.timeoutS ?? 30;
    await writeFile(
      path,
      JSON.stringify({
        program: request.program,
        argv: request.argv,
        stdin: request.stdin ?? null,
        functions: request.functions,
        samples: request.samples ?? 16,
        timeout,
      }),
    );
    const { stdout } = await run(python, [repositoryPath("src", "tools", "frida", "trace.py"), path], {
      timeout: (timeout + 60) * 1000,
      maxBuffer: 256 * 1024 * 1024,
    });
    return JSON.parse(stdout.trim().split("\n").pop() ?? "{}") as TraceResult;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
