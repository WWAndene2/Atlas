// atlas record behaviour <program> [--stdin <text>] [--input <file>]... [--output <name>]... [--env K=V]... [--timeout
// <s>] [--vary <regex>]... [-- <arguments>]: runs the original on a scenario and records what it did. atlas verify behaviour <original>
// <reconstruction>: replays every recorded scenario against the reconstruction. atlas blame behaviour <original>
// <hyp>: the functions a behaviour the rebuilt program fails comes from. atlas fuzz behaviour <original>
// <reconstruction>: mutants of the recorded inputs on which the two differ, recorded as behaviours. atlas coverage
// behaviour <original>: the translated functions the recorded behaviours reach. atlas copy behaviour <reference>
// <target>: behaviours of one build carried to another build of the same program.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import type { GraphStore } from "../../graph/index.js";
import { NotFoundError } from "../../orchestrator/function-context.js";
import { InvalidScenarioError, recordBehaviour, UnstableBehaviourError } from "../../orchestrator/record-behaviour.js";
import { replayBehaviour } from "../../orchestrator/replay-behaviour.js";
import { blameBehaviour } from "../../orchestrator/blame-behaviour.js";
import { fuzzBehaviour } from "../../orchestrator/fuzz-behaviour.js";
import { coverageBehaviour } from "../../orchestrator/coverage-behaviour.js";
import { copyBehaviour } from "../../orchestrator/copy-behaviour.js";
import { encode, type Scenario } from "../../verify/replay/run-scenario.js";
import { CliError, type Output } from "../output.js";

export interface RecordOptions {
  stdin?: string;
  input?: string[];
  output?: string[];
  env?: string[];
  timeout?: string;
  vary?: string[];
  each?: string;
  agent?: string;
}

const RECORD_USAGE =
  "usage: atlas record behaviour <program> [--stdin <text>] [--input <file>]... [--output <name>]... " +
  "[--env K=V]... [--timeout <seconds>] [--vary <regex>]... [--each <dir>] [-- <arguments>] (runs the program: only one you chose to run; with --each, one scenario per file, {} in the arguments its name)";

export async function runRecordBehaviour(store: GraphStore, args: string[], options: RecordOptions): Promise<Output> {
  const [what, program, ...argv] = args;
  if (what !== "behaviour" || program === undefined) throw new CliError("usage", RECORD_USAGE);
  if (!existsSync(program)) throw new CliError("not_found", `no file ${program}`);
  const env: Record<string, string> = {};
  for (const pair of options.env ?? []) {
    const at = pair.indexOf("=");
    if (at <= 0) throw new CliError("usage", `--env ${pair}: expected NAME=value`);
    env[pair.slice(0, at)] = pair.slice(at + 1);
  }
  const timeout = options.timeout !== undefined ? Number(options.timeout) : undefined;
  if (timeout !== undefined && !(timeout > 0)) throw new CliError("usage", `--timeout ${options.timeout}: seconds`);
  const inputs = (options.input ?? []).map((path) => {
    if (!existsSync(path)) throw new CliError("not_found", `no input file ${path}`);
    return { name: basename(path), content: encode(readFileSync(path)) };
  });
  const scenario: Scenario = {
    argv,
    ...(options.stdin !== undefined ? { stdin: options.stdin } : {}),
    ...(Object.keys(env).length > 0 ? { env } : {}),
    ...(inputs.length > 0 ? { inputs } : {}),
    ...(options.output !== undefined && options.output.length > 0 ? { outputs: options.output } : {}),
    ...(timeout !== undefined ? { timeout_s: timeout } : {}),
    ...(options.vary !== undefined && options.vary.length > 0 ? { vary: options.vary } : {}),
  };
  if (options.each !== undefined) return recordEach(store, program, scenario, options.each, options.agent);
  try {
    const { hypothesis, created } = await recordBehaviour(store, program, scenario, options.agent);
    const exit = (hypothesis.value as { expected: { exit: number | string } }).expected.exit;
    return {
      data: { hypothesis, created },
      text: `${hypothesis.id}: ${created ? "recorded" : "already recorded"} (exit ${String(exit)})`,
    };
  } catch (error) {
    if (error instanceof NotFoundError) throw new CliError("not_found", error.message);
    if (error instanceof UnstableBehaviourError) throw new CliError("failed", error.message);
    if (error instanceof InvalidScenarioError) throw new CliError("usage", error.message);
    throw error;
  }
}

/**
 * --each <dir>: one scenario per file of the directory (a test suite), the file added to the inputs and every {} in
 * the arguments replaced by its name. A scenario the program does not repeat is counted and skipped, so one flaky
 * test does not stop the suite.
 */
async function recordEach(
  store: GraphStore,
  program: string,
  base: Scenario,
  dir: string,
  agent: string | undefined,
): Promise<Output> {
  if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new CliError("not_found", `no directory ${dir}`);
  const files = readdirSync(dir)
    .filter((f) => statSync(join(dir, f)).isFile())
    .sort();
  if (!base.argv.some((a) => a.includes("{}"))) {
    throw new CliError("usage", "--each: name the file in the arguments with {} (e.g. -- {} for a script)");
  }
  const recorded: string[] = [];
  const unstable: string[] = [];
  for (const file of files) {
    const scenario: Scenario = {
      ...base,
      argv: base.argv.map((a) => a.split("{}").join(file)),
      inputs: [...(base.inputs ?? []), { name: file, content: encode(readFileSync(join(dir, file))) }],
    };
    try {
      recorded.push((await recordBehaviour(store, program, scenario, agent)).hypothesis.id);
    } catch (error) {
      if (!(error instanceof UnstableBehaviourError)) throw error;
      unstable.push(file);
    }
  }
  return {
    data: { recorded, unstable },
    text:
      `${recorded.length} of ${files.length} files recorded as behaviours` +
      (unstable.length > 0 ? `; not repeatable, skipped: ${unstable.join(", ")}` : ""),
  };
}

export async function runVerifyBehaviour(store: GraphStore, args: string[]): Promise<Output> {
  const [, original, reconstruction, ...extra] = args;
  if (original === undefined || reconstruction === undefined || extra.length > 0) {
    throw new CliError(
      "usage",
      "usage: atlas verify behaviour <original> <reconstruction> (runs the reconstruction on every recorded scenario)",
    );
  }
  for (const path of [original, reconstruction])
    if (!existsSync(path)) throw new CliError("not_found", `no file ${path}`);
  try {
    const replay = await replayBehaviour(store, original, reconstruction);
    const passed = replay.results.filter((r) => r.result === "pass").length;
    const failed = replay.results.filter((r) => r.result === "fail");
    return {
      data: replay,
      text:
        `${passed} of ${replay.results.length} behaviours reproduced` +
        failed.map((r) => `\n  ${r.hypothesis} ${JSON.stringify(r.argv)}: ${r.differences.join("; ")}`).join(""),
    };
  } catch (error) {
    if (error instanceof NotFoundError) throw new CliError("not_found", error.message);
    throw error;
  }
}

export async function runBlameBehaviour(store: GraphStore, args: string[]): Promise<Output> {
  const [what, original, behaviour, ...extra] = args;
  if (what !== "behaviour" || original === undefined || behaviour === undefined || extra.length > 0) {
    throw new CliError(
      "usage",
      "usage: atlas blame behaviour <original> <hyp_id> (rebuilds and runs the program many times: x86-64 Linux)",
    );
  }
  if (!existsSync(original)) throw new CliError("not_found", `no file ${original}`);
  try {
    const blame = await blameBehaviour(store, original, behaviour);
    const text =
      blame.result === "reproduced"
        ? `${behaviour}: reproduced by the rebuilt program, nothing to blame (${blame.rebuilds} rebuilds)`
        : blame.result === "not_functions"
          ? `${behaviour}: fails with every function run as the original's code too: not a function's fault ` +
            `(${blame.differences.join("; ")})`
          : `${behaviour}: ${blame.differences.join("; ")}; in ${blame.rebuilds} rebuilds, narrowed to\n` +
            blame.culprits
              .map(
                (c) =>
                  `  ${c.likely ? "likely " : "caller "}${c.id}${c.label !== undefined ? ` ${c.label}` : ""}` +
                  ` (${c.rewritten ? "its verified rewrite" : "its translation"})`,
              )
              .join("\n");
    return { data: blame, text };
  } catch (error) {
    if (error instanceof NotFoundError) throw new CliError("not_found", error.message);
    throw error;
  }
}

export async function runFuzzBehaviour(
  store: GraphStore,
  args: string[],
  options: { rounds?: string; seed?: string },
): Promise<Output> {
  const [what, original, reconstruction, ...extra] = args;
  if (what !== "behaviour" || original === undefined || reconstruction === undefined || extra.length > 0) {
    throw new CliError(
      "usage",
      "usage: atlas fuzz behaviour <original> <reconstruction> [--rounds <n>] [--seed <n>] (runs both programs)",
    );
  }
  for (const path of [original, reconstruction])
    if (!existsSync(path)) throw new CliError("not_found", `no file ${path}`);
  const number = (value: string | undefined, name: string) => {
    if (value === undefined) return undefined;
    const n = Number(value);
    if (!Number.isInteger(n) || n < 0) throw new CliError("usage", `--${name} ${value}: a whole number`);
    return n;
  };
  const rounds = number(options.rounds, "rounds");
  const seed = number(options.seed, "seed");
  try {
    const fuzz = await fuzzBehaviour(store, original, reconstruction, {
      ...(rounds !== undefined ? { rounds } : {}),
      ...(seed !== undefined ? { seed } : {}),
    });
    return {
      data: fuzz,
      text:
        `${fuzz.rounds} mutants tried (${fuzz.unstable} the original does not repeat): ` +
        `${fuzz.found.length} on which the reconstruction differs, recorded as behaviours` +
        fuzz.found.map((f) => `\n  ${f.hypothesis}: ${f.differences.join("; ")}`).join(""),
    };
  } catch (error) {
    if (error instanceof NotFoundError) throw new CliError("not_found", error.message);
    throw error;
  }
}

export async function runCoverageBehaviour(store: GraphStore, args: string[]): Promise<Output> {
  const [what, original, ...extra] = args;
  if (what !== "behaviour" || original === undefined || extra.length > 0) {
    throw new CliError(
      "usage",
      "usage: atlas coverage behaviour <original> (rebuilds the program and runs every recorded behaviour: x86-64)",
    );
  }
  if (!existsSync(original)) throw new CliError("not_found", `no file ${original}`);
  try {
    const c = await coverageBehaviour(store, original);
    const percent = c.translated > 0 ? ((100 * c.covered) / c.translated).toFixed(1) : "0";
    return {
      data: c,
      text:
        `${c.covered} of ${c.translated} translated functions reached by ${c.behaviours.length} behaviours (${percent}%)` +
        c.behaviours
          .map((b) => `\n  ${b.hypothesis} ${JSON.stringify(b.argv)}: ${b.reached} reached, ${b.added} new`)
          .join("") +
        `\nlargest not reached:` +
        c.uncovered.map((u) => `\n  ${u.id}${u.label !== undefined ? ` ${u.label}` : ""} (${u.size} bytes)`).join(""),
    };
  } catch (error) {
    if (error instanceof NotFoundError) throw new CliError("not_found", error.message);
    throw error;
  }
}

export async function runCopyBehaviour(store: GraphStore, args: string[]): Promise<Output> {
  const [what, reference, target, ...extra] = args;
  if (what !== "behaviour" || reference === undefined || target === undefined || extra.length > 0) {
    throw new CliError(
      "usage",
      "usage: atlas copy behaviour <reference> <target> (another build of the same program, both loaded)",
    );
  }
  for (const path of [reference, target]) if (!existsSync(path)) throw new CliError("not_found", `no file ${path}`);
  try {
    const result = await copyBehaviour(store, reference, target);
    return {
      data: result,
      text: `${result.copied.length} behaviours copied as inferred (${result.already} already there)`,
    };
  } catch (error) {
    if (error instanceof NotFoundError) throw new CliError("not_found", error.message);
    throw error;
  }
}
