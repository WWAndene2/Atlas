// atlas check format <file.ksy> <files...> [--agent <name>] [--binary <bin_>]
import { existsSync, readFileSync } from "node:fs";
import type { GraphStore } from "../../graph/index.js";
import { checkFormat } from "../../orchestrator/check-format.js";
import { NotFoundError } from "../../orchestrator/function-context.js";
import { KaitaiUnavailableError, KsyError } from "../../tools/kaitai/index.js";
import { CliError, type Output } from "../output.js";

export async function runCheckFormat(
  store: GraphStore,
  args: string[],
  options: { agent?: string; binary?: string },
): Promise<Output> {
  const [ksy, ...files] = args;
  if (ksy === undefined || files.length === 0) {
    throw new CliError("usage", "usage: atlas check format <file.ksy> <files...> [--agent <name>] [--binary <bin_>]");
  }
  for (const f of [ksy, ...files]) if (!existsSync(f)) throw new CliError("not_found", `no file ${f}`);
  try {
    const r = await checkFormat(store, readFileSync(ksy, "utf8"), files, options);
    return {
      data: r,
      text: `${r.format} (${r.hypothesis.id}): ${r.hypothesis.verification?.result ?? ""} (${r.hypothesis.verification?.details ?? ""}) -> ${r.hypothesis.confidence}`,
    };
  } catch (error) {
    if (error instanceof NotFoundError) throw new CliError("not_found", error.message);
    if (error instanceof KsyError) throw new CliError("failed", error.message);
    if (error instanceof KaitaiUnavailableError) throw new CliError("no_engine", error.message);
    throw error;
  }
}
