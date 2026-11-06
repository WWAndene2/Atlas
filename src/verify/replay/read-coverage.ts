// The coverage a rebuilt program wrote (ATLAS_COVERAGE: one function address per line, at exit), as a set; or
// undefined when the program wrote none (a program that does not report coverage, or one that did not exit).
import { readFile } from "node:fs/promises";

export async function readCoverage(path: string): Promise<Set<string> | undefined> {
  const text = await readFile(path, "utf8").catch(() => undefined);
  if (text === undefined) return undefined;
  return new Set(text.split("\n").filter((line) => line !== ""));
}
