// How the CLI writes results and errors: one JSON document with --json, short text otherwise.
import { NoEngineError } from "../orchestrator/load-target.js";
import { NotFoundError } from "../orchestrator/function-context.js";

export interface Output {
  /** The --json document. */
  data: unknown;
  /** The text form. */
  text: string;
}

export class CliError extends Error {
  constructor(
    readonly code: "usage" | "not_found" | "no_engine" | "failed",
    message: string,
  ) {
    super(message);
    this.name = "CliError";
  }
}

export function print(output: Output, json: boolean): void {
  process.stdout.write(
    json ? `${JSON.stringify(output.data, null, 2)}\n` : output.text.endsWith("\n") ? output.text : `${output.text}\n`,
  );
}

function codeOf(error: unknown): CliError["code"] {
  if (error instanceof CliError) return error.code;
  if (error instanceof NotFoundError) return "not_found";
  if (error instanceof NoEngineError) return "no_engine";
  return "failed";
}

export function fail(error: unknown, json: boolean): number {
  const code = codeOf(error);
  const message = error instanceof Error ? error.message : String(error);
  if (json) process.stdout.write(`${JSON.stringify({ error: { code, message } }, null, 2)}\n`);
  else process.stderr.write(`atlas: ${message}\n`);
  return code === "usage" ? 2 : 1;
}
