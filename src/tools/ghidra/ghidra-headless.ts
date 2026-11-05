// Runs Ghidra headless on one binary and returns its analysis. The only place Atlas starts Ghidra.
import { spawn } from "node:child_process";
import { closeSync, existsSync, openSync, readFileSync, readSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { repositoryPath } from "../../graph/index.js";
import { isPositionIndependentElf } from "../binary-header.js";
import type { Architecture, EngineAnalysis, EngineInput } from "../engine-analysis.js";
import { toolsDir } from "../tools-dir.js";
import { parseGhidraDecompile, type DecompiledFunction } from "./ghidra-decompile.js";
import { parseGhidraExport } from "./ghidra-export.js";

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

// Ghidra's language for each architecture Atlas names.
const GHIDRA_LANGUAGE: Record<Architecture, string> = {
  x86: "x86:LE:32:default",
  x86_64: "x86:LE:64:default",
  "arm-v5te": "ARM:LE:32:v5t",
  "arm-v6k": "ARM:LE:32:v6",
  "arm-v7": "ARM:LE:32:v7",
  arm64: "AARCH64:LE:64:v8A",
  mips: "MIPS:BE:32:default",
  mipsel: "MIPS:LE:32:default",
  ppc: "PowerPC:BE:32:default",
  ppc64: "PowerPC:BE:64:default",
};

function importArguments(input: EngineInput): string[] {
  if (input.raw === undefined) {
    // Keep the file's own addresses: Ghidra rebases position-independent ELF files to 0x100000 by default, which
    // would make every address disagree with the symbol table and with other engines. Only those: an executable
    // linked at a fixed address (MIPS at 0x400000, PowerPC at 0x10000000...) already loads where its addresses say,
    // and the option would move it to 0 (measured: every MIPS and PowerPC Lua address wrong until this check).
    return isPositionIndependentElf(readHead(input.path)) ? ["-loader-imagebase", "0"] : [];
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

function readHead(path: string): Uint8Array {
  const fd = openSync(path, "r");
  try {
    const buffer = new Uint8Array(64);
    const n = readSync(fd, buffer, 0, 64, 0);
    return buffer.subarray(0, n);
  } finally {
    closeSync(fd);
  }
}

export interface GhidraRunOptions {
  /** From locateGhidra, which checks the version. */
  installDir: string;
  /** Upper bound on the whole run, in milliseconds; defaults to ATLAS_GHIDRA_TIMEOUT_MINUTES, else 6 hours. */
  timeoutMs?: number;
}

// A whole game can keep Ghidra's auto-analysis busy for hours; the bound only stops a run that has hung.
function defaultTimeoutMs(env: NodeJS.ProcessEnv = process.env): number {
  const minutes = Number(env.ATLAS_GHIDRA_TIMEOUT_MINUTES);
  return (Number.isFinite(minutes) && minutes > 0 ? minutes : 360) * 60 * 1000;
}

/**
 * Runs analyzeHeadless. Its standard output is a progress log that grows with the target (megabytes on a large
 * game), so it is discarded rather than buffered; the last 64 KiB of standard error are kept for the failure message.
 */
function runHeadless(command: string, args: string[], timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    // Its own process group: analyzeHeadless is a launcher that starts Java, and a timeout must stop both.
    const child = spawn(command, args, { stdio: ["ignore", "ignore", "pipe"], detached: true });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr = (stderr + chunk).slice(-64 * 1024);
    });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
    }, timeoutMs);
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else if (timedOut) reject(new Error(`Ghidra stopped after ${timeoutMs / 60000} minutes`));
      else
        reject(new Error(`Ghidra exited with ${code ?? signal}: ${stderr.trim().split("\n").slice(-5).join(" | ")}`));
    });
  });
}

/** Imports `input` into a fresh temporary project, runs one Atlas script on it and returns what the script wrote. */
async function runScript(
  input: EngineInput,
  options: GhidraRunOptions,
  script: string,
  scriptArgs: string[],
): Promise<string> {
  const work = await mkdtemp(join(tmpdir(), "atlas-ghidra-"));
  const output = join(work, "output.json");
  try {
    await runHeadless(
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
        script,
        output,
        ...scriptArgs,
        "-deleteProject",
      ],
      options.timeoutMs ?? defaultTimeoutMs(),
    );
    if (!existsSync(output)) throw new Error(`Ghidra's ${script} wrote nothing for ${input.path}`);
    return await readFile(output, "utf8");
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

export async function analyseWithGhidra(input: EngineInput, options: GhidraRunOptions): Promise<EngineAnalysis> {
  return parseGhidraExport(await runScript(input, options, "AtlasExport.java", []));
}

/** Decompiles the functions at `addresses` (every function with a body when omitted) to C. */
export async function decompileWithGhidra(
  input: EngineInput,
  options: GhidraRunOptions,
  addresses?: string[],
): Promise<DecompiledFunction[]> {
  // The analysis is redone here: Ghidra keeps no project between runs (each target is analysed in a fresh one).
  const args = addresses === undefined ? [] : [addresses.join(",")];
  return parseGhidraDecompile(await runScript(input, options, "AtlasDecompile.java", args));
}
