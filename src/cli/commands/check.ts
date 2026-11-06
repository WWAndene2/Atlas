// atlas check functions <file> [--arch <a> --base <0x..>]: Rizin's functions set beside the graph's.
import { existsSync } from "node:fs";
import type { GraphStore } from "../../graph/index.js";
import { crossCheckFile } from "../../orchestrator/cross-check-functions.js";
import { NotFoundError } from "../../orchestrator/function-context.js";
import type { EngineInput } from "../../tools/engine-analysis.js";
import { RizinUnavailableError } from "../../tools/rizin/index.js";
import { CliError, type Output } from "../output.js";

export async function runCheckFunctions(store: GraphStore, args: string[], raw: EngineInput["raw"]): Promise<Output> {
  const [what, path, ...extra] = args;
  if (what !== "functions" || path === undefined || extra.length > 0) {
    throw new CliError("usage", "usage: atlas check functions <file> [--arch <a> --base <0x..>]");
  }
  if (!existsSync(path)) throw new CliError("not_found", `no file ${path}`);
  try {
    const results = await crossCheckFile(store, path, raw);
    const text = results
      .map(
        (r) =>
          `${r.label}: ${r.agreed} functions found by both engines, ${r.onlyGraph.length} only by Ghidra, ` +
          `${r.onlyRizin.length} only by Rizin, ${r.sizeDiffers.length} with another size (evidence ${r.evidence})`,
      )
      .join("\n");
    return { data: { binaries: results }, text };
  } catch (error) {
    if (error instanceof NotFoundError) throw new CliError("not_found", error.message);
    if (error instanceof RizinUnavailableError) throw new CliError("no_engine", error.message);
    throw error;
  }
}
