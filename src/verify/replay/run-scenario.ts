// Runs a program on a behaviour scenario and compares what it did with what was expected: the replay check, the
// acceptance test of a whole program (a behaviour hypothesis, docs/ARCHITECTURE.md). The same conditions every run,
// so a reconstruction and its original see the same thing: a fresh working directory holding the scenario's input
// files, argv[0] "program" (messages that name the program then match), a fixed environment (PATH, HOME at the
// working directory, LC_ALL=C, TZ=UTC, then the scenario's own variables), the scenario's standard input, a time
// limit. Runs the program natively: only programs the caller chose to run.
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

/** Bytes as text when they are valid UTF-8, else base64: readable in the graph, exact either way. */
export type Bytes = { text: string } | { base64: string };

export interface Scenario {
  argv: string[];
  stdin?: string;
  env?: Record<string, string>;
  /** Files the program finds in its working directory (by name, no directories). */
  inputs?: { name: string; content: Bytes }[];
  /** Files it writes there that the outcome includes. */
  outputs?: string[];
  timeout_s?: number;
  /**
   * What legitimately varies from run to run (a clock, a process ID): regular expressions (JavaScript syntax) whose
   * matches in standard output and error and in text output files are masked in both outcomes before they are
   * compared. Everything else must still be the same, byte for byte.
   */
  vary?: string[];
}

export interface Outcome {
  stdout: Bytes;
  stderr: Bytes;
  /** The exit code, or the signal that ended the program ("SIGSEGV"), or "timeout". */
  exit: number | string;
  /** Each output file's content, or null when the program did not write it. */
  files: Record<string, Bytes | null>;
}

export function encode(bytes: Buffer): Bytes {
  const text = bytes.toString("utf8");
  return Buffer.from(text, "utf8").equals(bytes) ? { text } : { base64: bytes.toString("base64") };
}

export function decode(bytes: Bytes): Buffer {
  return "text" in bytes ? Buffer.from(bytes.text, "utf8") : Buffer.from(bytes.base64, "base64");
}

const MAX_OUTPUT = 16 << 20;

/**
 * `instrument`: environment variables for the tooling around the run (ATLAS_COVERAGE...), set on top of the
 * scenario's but not part of it: the program's behaviour is not meant to depend on them.
 */
export async function runScenario(
  given: string,
  scenario: Scenario,
  instrument: Record<string, string> = {},
): Promise<Outcome> {
  const program = resolve(given); // it runs in another directory
  const work = await mkdtemp(join(tmpdir(), "atlas-replay-"));
  try {
    for (const input of scenario.inputs ?? []) {
      if (basename(input.name) !== input.name) throw new Error(`input file ${input.name}: a name, not a path`);
      await writeFile(join(work, input.name), decode(input.content));
    }
    const env = {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      HOME: work,
      LC_ALL: "C",
      TZ: "UTC",
      ...(scenario.env ?? {}),
      ...instrument,
    };
    const run = await new Promise<{ stdout: Buffer; stderr: Buffer; exit: number | string }>((done, fail) => {
      // In its own process group, so that stopping it stops what it started too (a child holding the output open
      // would keep the run from ending).
      const child = spawn(program, scenario.argv, { cwd: work, env, argv0: "program", stdio: "pipe", detached: true });
      const stop = () => {
        try {
          if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
        } catch {
          child.kill("SIGKILL"); // the group is already gone
        }
      };
      const out: Buffer[] = [];
      const err: Buffer[] = [];
      let size = 0;
      let timedOut = false;
      const keep = (to: Buffer[]) => (chunk: Buffer) => {
        size += chunk.length;
        if (size <= MAX_OUTPUT) to.push(chunk);
        else stop();
      };
      child.stdout.on("data", keep(out));
      child.stderr.on("data", keep(err));
      const timer = setTimeout(
        () => {
          timedOut = true;
          stop();
        },
        (scenario.timeout_s ?? 60) * 1000,
      );
      child.on("error", (error) => {
        clearTimeout(timer);
        fail(error);
      });
      child.on("close", (code, signal) => {
        clearTimeout(timer);
        done({
          stdout: Buffer.concat(out),
          stderr: Buffer.concat(err),
          exit: timedOut ? "timeout" : size > MAX_OUTPUT ? "output_limit" : (code ?? signal ?? "unknown"),
        });
      });
      child.stdin.on("error", () => undefined); // a program that exits without reading its input
      child.stdin.end(scenario.stdin ?? "");
    });
    const files: Record<string, Bytes | null> = {};
    for (const name of scenario.outputs ?? []) {
      if (basename(name) !== name) throw new Error(`output file ${name}: a name, not a path`);
      try {
        files[name] = encode(await readFile(join(work, name)));
      } catch {
        files[name] = null;
      }
    }
    return { stdout: encode(run.stdout), stderr: encode(run.stderr), exit: run.exit, files };
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

/**
 * Where two outcomes differ, each as a short description (empty when they are the same), the parts matching `vary`
 * masked first (byte positions are then counted in the masked text).
 */
export function differences(expected: Outcome, got: Outcome, vary: string[] = []): string[] {
  const out: string[] = [];
  const patterns = vary.map((v) => new RegExp(v, "g"));
  // Matches of a varying part read as one placeholder; bytes that are not text are compared as they are.
  const masked = (b: Bytes): Buffer =>
    "text" in b
      ? Buffer.from(
          patterns.reduce((t, p) => t.replace(p, "<varies>"), b.text),
          "utf8",
        )
      : decode(b);
  const same = (a: Bytes | null, b: Bytes | null) => (a === null || b === null ? a === b : masked(a).equals(masked(b)));
  const first = (a: Bytes, b: Bytes) => {
    const x = masked(a);
    const y = masked(b);
    let i = 0;
    while (i < x.length && i < y.length && x[i] === y[i]) i++;
    return `first difference at byte ${i} (${x.length} expected, ${y.length} got)`;
  };
  if (!same(expected.stdout, got.stdout)) out.push(`stdout: ${first(expected.stdout, got.stdout)}`);
  if (!same(expected.stderr, got.stderr)) out.push(`stderr: ${first(expected.stderr, got.stderr)}`);
  if (expected.exit !== got.exit) out.push(`exit: ${String(expected.exit)} expected, ${String(got.exit)} got`);
  for (const [name, content] of Object.entries(expected.files)) {
    const other = got.files[name] ?? null;
    if (!same(content, other)) {
      out.push(
        content === null || other === null
          ? `file ${name}: ${content === null ? "not written" : "written"} expected, ${other === null ? "not written" : "written"} got`
          : `file ${name}: ${first(content, other)}`,
      );
    }
  }
  return out;
}

/**
 * How much longer than the scenario's time limit a reconstruction may run: translated code is slower than the
 * original's (Lua's constructs.lua test: 1.2 s natively, 61 s translated), and a reconstruction that is slow but
 * right must not read as a hang.
 */
export const RECONSTRUCTION_SLOWDOWN = 20;

/** The scenario as a reconstruction is run on it: the same, with the time limit widened. */
export function forReconstruction(scenario: Scenario): Scenario {
  return { ...scenario, timeout_s: (scenario.timeout_s ?? 60) * RECONSTRUCTION_SLOWDOWN };
}
