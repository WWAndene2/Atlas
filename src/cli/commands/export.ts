// atlas export [<file.jsonl>]
import { writeFileSync } from "node:fs";
import { exportJsonl, type GraphStore } from "../../graph/index.js";
import { CliError, type Output } from "../output.js";

export function runExport(store: GraphStore, args: string[]): Output {
  const [file, ...extra] = args;
  if (extra.length > 0) throw new CliError("usage", "usage: atlas export [<file.jsonl>]");
  const text = exportJsonl(store);
  if (file === undefined) return { data: { jsonl: text }, text };
  writeFileSync(file, text);
  const records = text.split("\n").filter((line) => line !== "").length;
  return { data: { file, records }, text: `${records} records written to ${file}` };
}
