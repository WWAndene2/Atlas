// Runs Ghidra headless on one binary and returns its analysis. The only place Atlas starts Ghidra.
import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { repositoryPath } from "../../graph/index.js";
import type { EngineAnalysis } from "../engine-analysis.js";
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

/** The Ghidra installation named by GHIDRA_INSTALL_DIR, checked to be the reviewed version. */
export function locateGhidra(env: NodeJS.ProcessEnv = process.env): string {
  const dir = env.GHIDRA_INSTALL_DIR;
  if (dir === undefined || dir === "") {
    throw new GhidraUnavailableError("GHIDRA_INSTALL_DIR is not set; run scripts/setup.sh");
  }
  const headless = join(dir, "support", "analyzeHeadless");
  const properties = join(dir, "Ghidra", "application.properties");
  if (!existsSync(headless) || !existsSync(properties)) throw new GhidraUnavailableError(`no Ghidra at ${dir}`);
  const version = /^application\.version=(.+)$/m.exec(readFileSync(properties, "utf8"))?.[1]?.trim();
  if (version !== GHIDRA_VERSION) {
    throw new GhidraUnavailableError(
      `Ghidra ${version ?? "of unknown version"} at ${dir}; Atlas needs ${GHIDRA_VERSION}`,
    );
  }
  return dir;
}

export interface GhidraRunOptions {
  /** From locateGhidra, which checks the version. */
  installDir: string;
  /** Upper bound on the whole run, in milliseconds. */
  timeoutMs?: number;
}

export async function analyseWithGhidra(binaryPath: string, options: GhidraRunOptions): Promise<EngineAnalysis> {
  const work = await mkdtemp(join(tmpdir(), "atlas-ghidra-"));
  const output = join(work, "export.json");
  try {
    await run(
      join(options.installDir, "support", "analyzeHeadless"),
      [
        work,
        "atlas",
        "-import",
        binaryPath,
        // Keep the file's own addresses: Ghidra rebases position-independent ELF files to 0x100000 by default,
        // which would make every address disagree with the symbol table and with other engines.
        "-loader-imagebase",
        "0",
        "-scriptPath",
        scriptDir(),
        "-postScript",
        "AtlasExport.java",
        output,
        "-deleteProject",
      ],
      { timeout: options.timeoutMs ?? 30 * 60 * 1000, maxBuffer: 64 * 1024 * 1024 },
    );
    if (!existsSync(output)) throw new Error(`Ghidra wrote no export for ${binaryPath}`);
    return parseGhidraExport(await readFile(output, "utf8"));
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
