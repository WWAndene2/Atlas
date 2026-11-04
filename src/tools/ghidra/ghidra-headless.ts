// Runs Ghidra headless on one binary and returns its analysis. The only place Atlas starts Ghidra.
import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { repositoryPath } from "../../graph/index.js";
import type { Architecture, EngineAnalysis, EngineInput } from "../engine-analysis.js";
import { toolsDir } from "../tools-dir.js";
import { parseGhidraExport } from "./ghidra-export.js";

const run = promisify(execFile);

/** The Ghidra release Atlas is reviewed and tested with (docs/DEPENDENCY_REVIEWS.md). */
export const GHIDRA_VERSION = "12.1.4";

export class GhidraUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GhidraUnavailableError";
  }
}

// The script ships as source: Ghidra compiles it itself.
const scriptDir = (): string => repositoryPath("src", "tools", "ghidra", "scripts");

/**
 * The Ghidra installation to use, checked to be the reviewed version: GHIDRA_INSTALL_DIR when set, else the one
 * scripts/setup.sh installs in the tools directory.
 */
export function locateGhidra(env: NodeJS.ProcessEnv = process.env): string {
  const dir = env.GHIDRA_INSTALL_DIR || join(toolsDir(env), `ghidra_${GHIDRA_VERSION}_PUBLIC`);
  const headless = join(dir, "support", "analyzeHeadless");
  const properties = join(dir, "Ghidra", "application.properties");
  if (!existsSync(headless) || !existsSync(properties)) {
    throw new GhidraUnavailableError(`no Ghidra at ${dir}; run scripts/setup.sh or set GHIDRA_INSTALL_DIR`);
  }
  const version = /^application\.version=(.+)$/m.exec(readFileSync(properties, "utf8"))?.[1]?.trim();
  if (version !== GHIDRA_VERSION) {
    throw new GhidraUnavailableError(
      `Ghidra ${version ?? "of unknown version"} at ${dir}; Atlas needs ${GHIDRA_VERSION}`,
    );
  }
  return dir;
}

// Ghidra's language for each architecture Atlas names. Little-endian throughout: the targets in view are.
const GHIDRA_LANGUAGE: Record<Architecture, string> = {
  x86: "x86:LE:32:default",
  x86_64: "x86:LE:64:default",
  "arm-v5te": "ARM:LE:32:v5t",
  "arm-v6k": "ARM:LE:32:v6",
  "arm-v7": "ARM:LE:32:v7",
  arm64: "AARCH64:LE:64:v8A",
};

function importArguments(input: EngineInput): string[] {
  if (input.raw === undefined) {
    // Keep the file's own addresses: Ghidra rebases position-independent ELF files to 0x100000 by default, which
    // would make every address disagree with the symbol table and with other engines.
    return ["-loader-imagebase", "0"];
  }
  return [
    "-loader",
    "BinaryLoader",
    "-loader-baseAddr",
    input.raw.base,
    "-processor",
    GHIDRA_LANGUAGE[input.raw.architecture],
  ];
}

export interface GhidraRunOptions {
  /** From locateGhidra, which checks the version. */
  installDir: string;
  /** Upper bound on the whole run, in milliseconds. */
  timeoutMs?: number;
}

export async function analyseWithGhidra(input: EngineInput, options: GhidraRunOptions): Promise<EngineAnalysis> {
  const work = await mkdtemp(join(tmpdir(), "atlas-ghidra-"));
  const output = join(work, "export.json");
  try {
    await run(
      join(options.installDir, "support", "analyzeHeadless"),
      [
        work,
        "atlas",
        "-import",
        input.path,
        ...importArguments(input),
        "-scriptPath",
        scriptDir(),
        "-postScript",
        "AtlasExport.java",
        output,
        "-deleteProject",
      ],
      { timeout: options.timeoutMs ?? 30 * 60 * 1000, maxBuffer: 64 * 1024 * 1024 },
    );
    if (!existsSync(output)) throw new Error(`Ghidra wrote no export for ${input.path}`);
    return parseGhidraExport(await readFile(output, "utf8"));
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
