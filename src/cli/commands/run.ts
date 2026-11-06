// atlas run <file> --goal "<goal>" [--arch <a> --base <0x..>] [--report <file.md>]
import { existsSync, writeFileSync } from "node:fs";
import type { GraphStore } from "../../graph/index.js";
import { reportMarkdown, runTarget } from "../../orchestrator/run-target.js";
import type { EngineInput } from "../../tools/engine-analysis.js";
import { CliError, type Output } from "../output.js";

export async function runRun(
  store: GraphStore,
  args: string[],
  options: { goal?: string; report?: string; raw?: EngineInput["raw"] },
): Promise<Output> {
  const [path, ...extra] = args;
  if (path === undefined || extra.length > 0 || options.goal === undefined) {
    throw new CliError(
      "usage",
      'usage: atlas run <file> --goal "<goal>" [--arch <a> --base <0x..>] [--report <file.md>]',
    );
  }
  if (!existsSync(path)) throw new CliError("not_found", `no file ${path}`);
  const report = await runTarget(store, path, options.goal, options.raw);
  const markdown = reportMarkdown(report);
  if (options.report !== undefined) writeFileSync(options.report, markdown);
  return { data: report, text: markdown };
}
