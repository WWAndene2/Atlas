// Field accesses through pointer arguments (fields.py): angr runs each function of the whole binary from symbolic
// arguments and reports, per argument, the offsets and widths read or written through it.
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { repositoryPath } from "../../graph/index.js";

const run = promisify(execFile);

export interface FieldAccess {
  offset: number;
  size: number;
  read: boolean;
  write: boolean;
}

export interface FunctionFields {
  /** Argument index (0 = rdi) to the accesses through it. */
  args: Record<string, FieldAccess[]>;
  /** Every path returned within the bounds; else the accesses may be only some of them. */
  complete: boolean;
  error?: string;
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
      try {
        const { stdout } = await run(python, [repositoryPath("src", "tools", "angr", "fields.py"), path], {
          // Each function is stopped by an alarm after three times `seconds`; a stuck solver call can still outlast
          // it, so the whole run is bounded too, with time to load the binary.
          timeout: (todo.length * (seconds * 3 + 2) + 120) * 1000,
          maxBuffer: 256 * 1024 * 1024,
        });
        parseLines(stdout, out);
      } catch (error) {
        parseLines((error as { stdout?: string }).stdout ?? "", out);
      }
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
