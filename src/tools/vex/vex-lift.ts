// Static recompilation through VEX (lift.py): machine code of many functions to C in one run, for any architecture
// Atlas names. Runs in the tools Python environment (pyvex comes with angr).
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { repositoryPath } from "../../graph/index.js";
import type { Architecture } from "../engine-analysis.js";

const run = promisify(execFile);

/** archinfo's name and byte order for each architecture Atlas names. */
const ARCH: Record<Architecture, { name: string; endness: "Iend_LE" | "Iend_BE" }> = {
  x86: { name: "X86", endness: "Iend_LE" },
  x86_64: { name: "AMD64", endness: "Iend_LE" },
  "arm-v5te": { name: "ARMEL", endness: "Iend_LE" },
  "arm-v6k": { name: "ARMEL", endness: "Iend_LE" },
  "arm-v7": { name: "ARMEL", endness: "Iend_LE" },
  arm64: { name: "AARCH64", endness: "Iend_LE" },
  mips: { name: "MIPS32", endness: "Iend_BE" },
  mipsel: { name: "MIPS32", endness: "Iend_LE" },
  ppc: { name: "PPC32", endness: "Iend_BE" },
  ppc64: { name: "PPC64", endness: "Iend_BE" },
};

export function bigEndian(architecture: Architecture): boolean {
  return ARCH[architecture].endness === "Iend_BE";
}

export type LiftedFunction = { address: string; c: string } | { address: string; unsupported: string };

export async function liftFunctions(
  python: string,
  architecture: Architecture,
  functions: { address: number; code: string; thumb?: boolean }[],
  binary?: string,
): Promise<LiftedFunction[]> {
  const work = await mkdtemp(join(tmpdir(), "atlas-lift-"));
  try {
    const request = join(work, "request.json");
    await writeFile(
      request,
      JSON.stringify({ arch: ARCH[architecture].name, endness: ARCH[architecture].endness, binary, functions }),
    );
    const { stdout } = await run(python, [repositoryPath("src", "tools", "vex", "lift.py"), request], {
      maxBuffer: 1 << 30,
      timeout: 3_600_000,
    });
    return stdout
      .split("\n")
      .filter((l) => l.startsWith("{"))
      .map((l) => JSON.parse(l) as LiftedFunction);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

/** The runtime header the translations include. */
export const RUNTIME_HEADER = repositoryPath("src", "tools", "vex", "atlas_lift.h");
