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

export async function functionFields(
  python: string,
  binary: string,
  functions: number[],
  options: { positionIndependent: boolean; seconds?: number; maxSteps?: number },
): Promise<Record<string, FunctionFields>> {
  const work = await mkdtemp(join(tmpdir(), "atlas-fields-"));
  try {
    const path = join(work, "request.json");
    const seconds = options.seconds ?? 4;
    await writeFile(
      path,
      JSON.stringify({
        binary,
        pie: options.positionIndependent,
        functions,
        seconds,
        max_steps: options.maxSteps ?? 40,
      }),
    );
    const { stdout } = await run(python, [repositoryPath("src", "tools", "angr", "fields.py"), path], {
      // fields.py stops each function after three times `seconds` at most (an alarm), plus loading the binary.
      timeout: (functions.length * (seconds * 3 + 2) + 120) * 1000,
      maxBuffer: 256 * 1024 * 1024,
    });
    return (JSON.parse(stdout.trim().split("\n").pop() ?? "{}") as { functions: Record<string, FunctionFields> })
      .functions;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
