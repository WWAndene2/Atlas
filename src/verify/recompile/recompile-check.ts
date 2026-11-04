// The recompile check: compiles a function's C with the target's toolchain and compares the machine code with the
// original function's bytes. A match means the C is a faithful source for that function, byte for byte, which is
// what recompiling a program needs.
//
// The compiler produces an object file, so call targets and data addresses are not known yet: those bytes are holes
// that relocations fill at link time. The check masks every byte a relocation covers, in both the candidate and the
// original, and compares the rest. Object files are ELF or COFF (object-file.ts), so one checker serves Linux,
// Android, consoles and Windows toolchains alike.
//
// Validated on Lua (x86-64, GCC 13.3, -O2): the real source of every function whose name survives in the stripped
// binary, compiled and checked, passes for 152 of 154. Known limit, the other two: a tail jump to a function of the
// same source file is resolved by the assembler in the original (a 2-byte short jump) but is a relocation when the
// function is compiled alone (a 5-byte jump). Hence the group form: with `last`, the source defines a run of
// consecutive functions in their original order, compiled without -ffunction-sections so the assembler lays them out
// and resolves the jumps between them as in the original, and the run is compared as one block.
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { functionRun, functionSection, readObjectFile } from "./object-file.js";

const run = promisify(execFile);

/** How the original was compiled: the compiler command and its flags. */
export interface Toolchain {
  cc: string;
  flags: string[];
}

export interface RecompileRequest {
  /** A translation unit defining the function (with whatever declarations it needs). */
  source: string;
  /** Name of the function in that source (the first of the run, with `last`). */
  name: string;
  /** With a run of neighbouring functions: the name of the run's last function. */
  last?: string;
  /** The file's bytes from the function's entry (the run's first) on: the candidate must match a prefix of them. */
  original: Uint8Array;
  /** The engine's view of the length (to the end of the run's last function): the candidate covers at least this. */
  minimumSize: number;
  toolchain: Toolchain;
}

export type RecompileResult =
  | { result: "pass"; size: number; masked: number }
  | { result: "fail"; reason: "compile_error"; details: string }
  | { result: "fail"; reason: "not_found"; details: string }
  | {
      result: "fail";
      reason: "mismatch";
      size: number;
      originalSize: number;
      firstDifference: number;
      differing: number;
    };

export async function recompileCheck(request: RecompileRequest): Promise<RecompileResult> {
  const work = await mkdtemp(join(tmpdir(), "atlas-recompile-"));
  try {
    const source = join(work, "unit.c");
    const object = join(work, "unit.o");
    await writeFile(source, request.source);
    try {
      // Alone: one section per function, so its code is found by name and nothing else is mixed in. As a run: one
      // section for all, laid out by the assembler as in the original.
      const sectioning = request.last === undefined ? ["-ffunction-sections"] : [];
      await run(request.toolchain.cc, [...request.toolchain.flags, ...sectioning, "-c", source, "-o", object]);
    } catch (error) {
      const stderr = (error as { stderr?: string }).stderr ?? (error as Error).message;
      return { result: "fail", reason: "compile_error", details: stderr.slice(0, 4000) };
    }
    const objectFile = await readObjectFile(object);
    const code =
      request.last === undefined
        ? functionSection(objectFile, request.name)
        : functionRun(objectFile, request.name, request.last);
    if (code === undefined) {
      const what = request.last === undefined ? request.name : `${request.name} to ${request.last} in one section`;
      return { result: "fail", reason: "not_found", details: `no ${what} in the object` };
    }
    const compiled = code.bytes;
    const holes = code.relocations;

    // The candidate must cover the function as the engine sees it and fit before the next function; then every
    // byte not under a relocation must equal the original's.
    const original = request.original;
    const mask = new Uint8Array(compiled.length);
    let masked = 0;
    for (const h of holes) {
      for (let i = h.offset; i < h.offset + h.width && i < mask.length; i++) {
        if (mask[i] === 0) masked++;
        mask[i] = 1;
      }
    }
    let differing = 0;
    let firstDifference = -1;
    for (let i = 0; i < Math.min(compiled.length, original.length); i++) {
      if (mask[i] === 0 && compiled[i] !== original[i]) {
        differing++;
        if (firstDifference < 0) firstDifference = i;
      }
    }
    const sizeOk = compiled.length >= request.minimumSize && compiled.length <= original.length;
    if (differing === 0 && sizeOk) return { result: "pass", size: compiled.length, masked };
    return {
      result: "fail",
      reason: "mismatch",
      size: compiled.length,
      originalSize: Math.max(request.minimumSize, Math.min(original.length, compiled.length)),
      firstDifference: firstDifference < 0 ? Math.min(compiled.length, original.length) : firstDifference,
      differing: differing + (sizeOk ? 0 : 1),
    };
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
