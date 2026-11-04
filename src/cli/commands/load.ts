// atlas load <binary>
import { existsSync } from "node:fs";
import type { GraphStore } from "../../graph/index.js";
import { loadTarget } from "../../orchestrator/load-target.js";
import { CliError, type Output } from "../output.js";

export async function runLoad(store: GraphStore, args: string[]): Promise<Output> {
  const [path, ...extra] = args;
  if (path === undefined || extra.length > 0) throw new CliError("usage", "usage: atlas load <binary>");
  if (!existsSync(path)) throw new CliError("not_found", `no file ${path}`);
  const engines = await loadTarget(store, path);
  const text = engines
    .map((e) =>
      e.loaded !== undefined
        ? `${e.engine}: ${e.loaded.functions} functions, ${e.loaded.calls} calls, ${e.loaded.strings} strings into ${e.loaded.binary}`
        : `${e.engine}: skipped (${e.skipped})`,
    )
    .join("\n");
  return { data: { engines }, text };
}
