// atlas infer fields <program> [--function <fn|0x>]...: the fields each function's pointer arguments point to.
import { existsSync } from "node:fs";
import type { GraphStore } from "../../graph/index.js";
import { fileSha256 } from "../../orchestrator/file-hash.js";
import { NotFoundError, resolveFunction } from "../../orchestrator/function-context.js";
import { inferFields } from "../../orchestrator/infer-fields.js";
import { binaryId } from "../../orchestrator/load-binary.js";
import { AngrUnavailableError } from "../../tools/angr/index.js";
import { CliError, type Output } from "../output.js";

export async function runInferFields(store: GraphStore, args: string[], functions: string[]): Promise<Output> {
  const [what, path, ...extra] = args;
  if (what !== "fields" || path === undefined || extra.length > 0) {
    throw new CliError("usage", "usage: atlas infer fields <program> [--function <fn|0x>]...");
  }
  if (!existsSync(path)) throw new CliError("not_found", `no file ${path}`);
  const binary = binaryId(await fileSha256(path));
  if (store.getNode(binary) === undefined)
    throw new CliError("not_found", `${path} is not loaded; atlas load it first`);
  try {
    const only = functions.length > 0 ? functions.map((f) => resolveFunction(store, f, binary).id) : undefined;
    const o = await inferFields(store, binary, path, only !== undefined ? { only } : {});
    return {
      data: o,
      text:
        `${o.withFields} of ${o.functions} functions access fields through pointer arguments ` +
        `(${o.complete} explored completely); checked against traces: ${o.checked.pass} confirmed, ${o.checked.fail} contradicted` +
        (o.failed > 0 ? `; ${o.failed} functions not analysed (angr failed)` : ""),
    };
  } catch (error) {
    if (error instanceof NotFoundError) throw new CliError("not_found", error.message);
    if (error instanceof AngrUnavailableError) throw new CliError("no_engine", error.message);
    if (error instanceof CliError) throw error;
    throw new CliError("failed", (error as Error).message);
  }
}
