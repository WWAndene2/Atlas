// Links a binary's translations into a program: for a host of the same architecture, with its verified rewrites in
// their place (link.py, x86-64 Linux ELF for now); or for a guest of another CPU, its system calls emulated
// (crosslink.py, statically linked 32-bit ARM Linux ELF for now).
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { repositoryPath } from "../../graph/index.js";

const run = promisify(execFile);

export interface LinkRequest {
  binary: string;
  lifted: string[];
  translated: number[];
  out: string;
  rewrites: { address: number; name: string; source: string; flags: string[] }[];
  /** The binary's functions by name (labels and name hypotheses) to their address. */
  functions: Record<string, number>;
  /** Where the image is mapped; the translations must have been made at the same base. */
  base: number;
}

export interface LinkOutcome {
  executable: string;
  imports: number;
  rewrites: number;
  rewrites_skipped: { address: number; reason: string }[];
}

export async function linkProgram(python: string, request: LinkRequest): Promise<LinkOutcome> {
  const work = await mkdtemp(join(tmpdir(), "atlas-link-"));
  try {
    const path = join(work, "request.json");
    await writeFile(
      path,
      JSON.stringify({ ...request, arch: "AMD64", runtime: repositoryPath("src", "tools", "vex") }),
    );
    const { stdout } = await run(python, [repositoryPath("src", "tools", "vex", "link.py"), path], {
      maxBuffer: 1 << 28,
      timeout: 3_600_000,
    });
    return JSON.parse(stdout.trim().split("\n").pop() ?? "{}") as LinkOutcome;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

export interface CrosslinkRequest {
  /** archinfo's name and byte order of the guest. */
  arch: string;
  endness: string;
  binary: string;
  lifted: string[];
  translated: number[];
  out: string;
  /** Where the image is mapped; the translations must have been made at the same base. */
  base: number;
}

export interface CrosslinkOutcome {
  executable: string;
  translated: number;
  entry: string;
}

export async function crosslinkProgram(python: string, request: CrosslinkRequest): Promise<CrosslinkOutcome> {
  const work = await mkdtemp(join(tmpdir(), "atlas-crosslink-"));
  try {
    const path = join(work, "request.json");
    await writeFile(path, JSON.stringify({ ...request, runtime: repositoryPath("src", "tools", "vex") }));
    const { stdout } = await run(python, [repositoryPath("src", "tools", "vex", "crosslink.py"), path], {
      maxBuffer: 1 << 28,
      timeout: 3_600_000,
    });
    return JSON.parse(stdout.trim().split("\n").pop() ?? "{}") as CrosslinkOutcome;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
