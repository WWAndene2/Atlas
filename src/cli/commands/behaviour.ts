// atlas record behaviour <program> [--stdin <text>] [--input <file>]... [--output <name>]... [--env K=V]... [--timeout
// <s>] [-- <arguments>]: runs the original on a scenario and records what it did. atlas verify behaviour <original>
// <reconstruction>: replays every recorded scenario against the reconstruction.
import { existsSync, readFileSync } from "node:fs";
import { basename } from "node:path";
import type { GraphStore } from "../../graph/index.js";
import { NotFoundError } from "../../orchestrator/function-context.js";
import { recordBehaviour, UnstableBehaviourError } from "../../orchestrator/record-behaviour.js";
import { replayBehaviour } from "../../orchestrator/replay-behaviour.js";
import { encode, type Scenario } from "../../verify/replay/run-scenario.js";
import { CliError, type Output } from "../output.js";

export interface RecordOptions {
  stdin?: string;
  input?: string[];
  output?: string[];
  env?: string[];
  timeout?: string;
  agent?: string;
}

const RECORD_USAGE =
  "usage: atlas record behaviour <program> [--stdin <text>] [--input <file>]... [--output <name>]... " +
  "[--env K=V]... [--timeout <seconds>] [-- <arguments>] (runs the program: only one you chose to run)";

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
