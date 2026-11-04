// Loads one binary with every engine that can run here. An engine that cannot run (not installed, wrong version) or
// fails is skipped and reported, so the target still loads with the others; only when none succeeds is it an error.
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { GraphStore } from "../graph/index.js";
import { ENGINES, type Engine } from "./engines.js";
import { loadAnalysis, type LoadResult } from "./load-binary.js";

export interface EngineOutcome {
  engine: string;
  loaded?: LoadResult;
  skipped?: string;
}

export class NoEngineError extends Error {
  constructor(readonly outcomes: EngineOutcome[]) {
    super(`no engine could load the binary: ${outcomes.map((o) => `${o.engine}: ${o.skipped}`).join("; ")}`);
    this.name = "NoEngineError";
  }
}

export async function loadTarget(
  store: GraphStore,
  binaryPath: string,
  engines: readonly Engine[] = ENGINES,
): Promise<EngineOutcome[]> {
  const sha256 = createHash("sha256")
    .update(await readFile(binaryPath))
    .digest("hex");
  const outcomes: EngineOutcome[] = [];
  for (const engine of engines) {
    try {
      const analyse = engine.prepare();
      const analysis = await analyse(binaryPath);
      // An engine reporting another file's hash would attach its facts to the wrong binary.
      if (analysis.sha256 !== sha256) throw new Error(`${engine.name} analysed a file with another SHA-256`);
      outcomes.push({ engine: engine.name, loaded: loadAnalysis(store, binaryPath, analysis) });
    } catch (error) {
      outcomes.push({ engine: engine.name, skipped: (error as Error).message });
    }
  }
  if (!outcomes.some((o) => o.loaded !== undefined)) throw new NoEngineError(outcomes);
  return outcomes;
}
