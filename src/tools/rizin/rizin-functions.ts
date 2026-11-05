// Rizin as a second analysis engine: the functions it finds in a binary, to set beside Ghidra's (a function both
// engines find is better founded than one only one of them finds). Rizin is installed by scripts/setup.sh in the
// tools directory, exactly the reviewed version (docs/DEPENDENCY_REVIEWS.md).
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import type { Architecture, EngineInput } from "../engine-analysis.js";
import { toolsDir } from "../tools-dir.js";

const run = promisify(execFile);

export const RIZIN_VERSION = "0.9.1";

export class RizinUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RizinUnavailableError";
  }
}

export interface RizinFunction {
  /** Lowercase hex with 0x, at the binary's own addresses. */
  address: string;
  size: number;
  label: string;
}

export function locateRizin(env: NodeJS.ProcessEnv = process.env): string {
  const rizin = join(toolsDir(env), `rizin-${RIZIN_VERSION}`, "bin", "rizin");
  if (!existsSync(rizin)) throw new RizinUnavailableError(`no Rizin at ${rizin}; run scripts/setup.sh`);
  return rizin;
}

/** Rizin's options for a raw image of each CPU family: architecture, bits, endianness. */
const RAW: Record<Architecture, string[]> = {
  x86: ["-a", "x86", "-b", "32"],
  x86_64: ["-a", "x86", "-b", "64"],
  "arm-v5te": ["-a", "arm", "-b", "32"],
  "arm-v6k": ["-a", "arm", "-b", "32"],
  "arm-v7": ["-a", "arm", "-b", "32"],
  arm64: ["-a", "arm", "-b", "64"],
  mips: ["-a", "mips", "-b", "32", "-E", "big"],
  mipsel: ["-a", "mips", "-b", "32"],
  ppc: ["-a", "ppc", "-b", "32", "-E", "big"],
  ppc64: ["-a", "ppc", "-b", "64", "-E", "big"],
};

export async function rizinFunctions(rizin: string, input: EngineInput, timeoutMs = 600_000): Promise<RizinFunction[]> {
  // -B 0 keeps a position-independent binary at its own addresses, as Ghidra's import does (ET_DYN at 0).
  const where = input.raw === undefined ? ["-B", "0"] : [...RAW[input.raw.architecture], "-m", input.raw.base];
  // A raw image has no entry point for Rizin to start from: the first byte is taken as code, as for Ghidra.
  const analyse = input.raw === undefined ? "aaa; aflj" : `af @ ${input.raw.base}; aaa; aflj`;
  const { stdout } = await run(rizin, ["-q", "-2", "-N", ...where, "-c", analyse, input.path], {
    timeout: timeoutMs,
    maxBuffer: 1 << 30,
  });
  const listed = JSON.parse(stdout.trim() || "[]") as { offset: number; size: number; name: string }[];
  return listed.map((f) => ({ address: `0x${f.offset.toString(16)}`, size: f.size, label: f.name }));
}
