// atlas trace <program> [--stdin <text>] [-- <arguments>]: runs the program under Frida and records what ran.
import { existsSync } from "node:fs";
import type { GraphStore } from "../../graph/index.js";
import { NotFoundError } from "../../orchestrator/function-context.js";
import { traceTarget } from "../../orchestrator/trace-target.js";
import { FridaUnavailableError } from "../../tools/frida/index.js";
import { CliError, type Output } from "../output.js";

export async function runTrace(store: GraphStore, args: string[], options: { stdin?: string }): Promise<Output> {
  const [program, ...argv] = args;
  if (program === undefined) {
    throw new CliError(
      "usage",
      "usage: atlas trace <program> [--stdin <text>] [-- <arguments>] (runs the program: only one you chose to run)",
    );
  }
  if (!existsSync(program)) throw new CliError("not_found", `no file ${program}`);
  try {
    const t = await traceTarget(store, program, argv, options.stdin !== undefined ? { stdin: options.stdin } : {});
    return {
      data: t,
      text:
        `${t.ran} functions ran (${t.exit}); ${t.unhooked} could not be hooked; ` +
        `${t.hypotheses.length} observed signatures recorded (evidence ${t.evidence})`,
    };
  } catch (error) {
    if (error instanceof NotFoundError) throw new CliError("not_found", error.message);
    if (error instanceof FridaUnavailableError) throw new CliError("no_engine", error.message);
    throw error;
  }
}
