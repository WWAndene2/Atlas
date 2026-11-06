// Links a binary's translations into a program: for a host of the same architecture, with its verified rewrites in
// their place (link.py, x86-64 Linux ELF for now); or for a guest of another CPU, its system calls emulated
// (crosslink.py, statically linked 32-bit ARM Linux ELF for now); or a Windows x64 program for this Linux host, its
// C library and kernel32 served (winlink.py).
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
  /** Graph addresses of functions run as the original's machine code instead of their translation or rewrite. */
  native?: number[];
}

export interface LinkOutcome {
  executable: string;
  imports: number;
  rewrites: number;
  rewrites_skipped: { address: number; reason: string }[];
  /** A Windows program's imports no service covers (winlink.py): the program stops if it calls one. */
  unserved?: string[];
  /** The output is a host shared library (from an AArch64 .so), not a program. */
  library?: boolean;
}

export async function linkProgram(python: string, request: LinkRequest): Promise<LinkOutcome> {
  return runLinker<LinkOutcome>(python, "link.py", { ...request, arch: "AMD64" });
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
  /**
   * The platform the guest runs on: Linux system calls (the default), a console's kernel ("ctr": the 3DS), or no
   * operating system ("bare").
   */
  profile?: "linux" | "ctr" | "bare";
  /** The window [low, high) of the machine's hardware registers: accesses in it go to the profile's devices. */
  devices?: [number, number];
}

export interface CrosslinkOutcome {
  executable: string;
  translated: number;
  entry: string;
}

export async function crosslinkProgram(python: string, request: CrosslinkRequest): Promise<CrosslinkOutcome> {
  return runLinker<CrosslinkOutcome>(python, "crosslink.py", request);
}

export interface WinlinkRequest {
  binary: string;
  lifted: string[];
  translated: number[];
  out: string;
}

export interface WinlinkOutcome {
  executable: string;
  imports: number;
  stubs: number;
  /** Imports the program has that no service covers: the program stops if it calls one. */
  unserved: string[];
}

export async function winlinkProgram(python: string, request: WinlinkRequest): Promise<WinlinkOutcome> {
  return runLinker<WinlinkOutcome>(python, "winlink.py", request);
}

export interface A64linkRequest {
  binary: string;
  lifted: string[];
  translated: number[];
  out: string;
  /** Where the image is mapped; the translations must have been made at the same base. */
  base: number;
}

export interface A64linkOutcome {
  executable: string;
  imports: number;
  /** Data imports the host's C library lacks, which the program provides itself. */
  own: string[];
}

export async function a64linkProgram(python: string, request: A64linkRequest): Promise<A64linkOutcome> {
  return runLinker<A64linkOutcome>(python, "a64link.py", request);
}

/** Runs a linker script on a request (written to a temporary file, with the runtime directory added) and returns the
 * JSON on the last line of its output. */
async function runLinker<T>(python: string, script: string, request: object): Promise<T> {
  const work = await mkdtemp(join(tmpdir(), "atlas-link-"));
  try {
    const path = join(work, "request.json");
    await writeFile(path, JSON.stringify({ ...request, runtime: repositoryPath("src", "tools", "vex") }));
    const { stdout } = await run(python, [repositoryPath("src", "tools", "vex", script), path], {
      maxBuffer: 1 << 28,
      timeout: 3_600_000,
    });
    return JSON.parse(stdout.trim().split("\n").pop() ?? "{}") as T;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
