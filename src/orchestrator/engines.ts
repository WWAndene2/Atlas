// The engines Atlas can run, each through its adapter in src/tools/<tool>/. Adding an engine means one entry here.
import type { EngineAnalysis } from "../tools/engine-analysis.js";
import { analyseWithGhidra, locateGhidra } from "../tools/ghidra/index.js";

export interface Engine {
  name: string;
  /** Throws, naming what is missing and how to get it, when the engine cannot run here. */
  prepare(): (binaryPath: string) => Promise<EngineAnalysis>;
}

export const ENGINES: readonly Engine[] = [
  {
    name: "ghidra",
    prepare() {
      const installDir = locateGhidra();
      return (binaryPath) => analyseWithGhidra(binaryPath, { installDir });
    },
  },
];
