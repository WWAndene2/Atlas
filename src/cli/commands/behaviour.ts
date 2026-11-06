// atlas record behaviour <program> [--stdin <text>] [--input <file>]... [--output <name>]... [--env K=V]... [--timeout
// <s>] [--vary <regex>]... [-- <arguments>]: runs the original on a scenario and records what it did. atlas verify behaviour <original>
// <reconstruction>: replays every recorded scenario against the reconstruction. atlas blame behaviour <original>
// <hyp>: the functions a behaviour the rebuilt program fails comes from. atlas fuzz behaviour <original>
// <reconstruction>: mutants of the recorded inputs on which the two differ, recorded as behaviours.
import { existsSync, readFileSync } from "node:fs";
import { basename } from "node:path";
import type { GraphStore } from "../../graph/index.js";
import { NotFoundError } from "../../orchestrator/function-context.js";
import { InvalidScenarioError, recordBehaviour, UnstableBehaviourError } from "../../orchestrator/record-behaviour.js";
import { replayBehaviour } from "../../orchestrator/replay-behaviour.js";
import { blameBehaviour } from "../../orchestrator/blame-behaviour.js";
import { fuzzBehaviour } from "../../orchestrator/fuzz-behaviour.js";
import { encode, type Scenario } from "../../verify/replay/run-scenario.js";
import { CliError, type Output } from "../output.js";

export interface RecordOptions {
  stdin?: string;
  input?: string[];
  output?: string[];
  env?: string[];
  timeout?: string;
  vary?: string[];
  agent?: string;
}

const RECORD_USAGE =
  "usage: atlas record behaviour <program> [--stdin <text>] [--input <file>]... [--output <name>]... " +
  "[--env K=V]... [--timeout <seconds>] [--vary <regex>]... [-- <arguments>] (runs the program: only one you chose to run)";

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
