// Field accesses through pointer arguments (fields.py): angr runs each function of the whole binary from symbolic
// arguments and reports, per argument, the offsets and widths read or written through it.
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { repositoryPath } from "../../graph/index.js";

export interface FieldAccess {
  offset: number;
  size: number;
  read: boolean;
  write: boolean;
}

export interface FunctionFields {
  /** Argument index (0 = rdi) to the accesses through it. */
  args: Record<string, FieldAccess[]>;
  /** Arguments handed unchanged to a callee: its parameter (register index) is the caller's argument `arg`. */
  passes?: { callee: string; register: number; arg: number }[];
  /** Every path returned within the bounds; else the accesses may be only some of them. */
  complete: boolean;
  error?: string;
}

/**
 * Runs the script and returns its output. Each function is stopped by an alarm after three times `seconds`, but a
 * solver call can hold the process past it: a process silent for longer than that (plus time to load the binary
 * before the first line) is killed, and what it wrote is kept.
 */
function watched(python: string, args: string[], seconds: number): Promise<string> {
  return new Promise((resolve) => {
    const child = spawn(python, args, { stdio: ["ignore", "pipe", "ignore"] });
    let stdout = "";
    let timer: NodeJS.Timeout;
    const arm = (s: number) => {
      clearTimeout(timer);
      timer = setTimeout(() => child.kill("SIGKILL"), s * 1000);
    };
    arm(seconds * 3 + 180);
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
      arm(seconds * 3 + 30);
    });
    child.on("close", () => {
      clearTimeout(timer);
      resolve(stdout);
    });
  });
}

function parseLines(stdout: string, into: Record<string, FunctionFields>): void {
  for (const line of stdout.split("\n")) {
    if (!line.startsWith("{")) continue;
    try {
      const { address, ...fields } = JSON.parse(line) as FunctionFields & { address: string };
      into[address] = fields;
    } catch {
      // A line cut short by the process ending: that function is retried.
    }
  }
}

/**
 * Runs fields.py on `functions`. A function can hold the solver past every bound; the process is then stopped, the
 * functions already written are kept, the one it was on is recorded as out of time, and the rest are run again.
 */
export async function functionFields(
  python: string,
  binary: string,
  functions: number[],
  options: { positionIndependent: boolean; seconds?: number; maxSteps?: number },
): Promise<Record<string, FunctionFields>> {
  const out: Record<string, FunctionFields> = {};
  const seconds = options.seconds ?? 4;
  let todo = functions;
  const work = await mkdtemp(join(tmpdir(), "atlas-fields-"));
  try {
    while (todo.length > 0) {
      const path = join(work, "request.json");
      await writeFile(
        path,
        JSON.stringify({
          binary,
          pie: options.positionIndependent,
          functions: todo,
          seconds,
          max_steps: options.maxSteps ?? 40,
        }),
      );
      parseLines(await watched(python, [repositoryPath("src", "tools", "angr", "fields.py"), path], seconds), out);
      const left = todo.filter((a) => out[`0x${a.toString(16)}`] === undefined);
      // The first function without an answer is the one the process was on: recorded, and the rest run again.
      const stuck = left[0];
      if (stuck !== undefined) out[`0x${stuck.toString(16)}`] = { args: {}, complete: false, error: "out of time" };
      todo = left.slice(1);
    }
    return out;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
