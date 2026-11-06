// The "it runs" path's last step: a binary's translations (lift-binary.ts) linked into a program, with every
// verified rewrite taking its translation's place where it can (src/tools/vex/rewrites.py says why not). The
// rewrites are compiled as they were verified: the binary's detected toolchain, Ghidra's prelude when they use it.
// A 32-bit ARM binary is linked for this x86-64 host as a guest of another CPU (crosslink.py), a Windows x64 program
// with its C library and kernel32 served (winlink.py), an AArch64 Linux program (an Android app's native code) with
// its imports served by the host's C library (a64link.py): translations only, in all three.
import { closeSync, openSync, readSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import type { GraphStore } from "../graph/index.js";
import { locateAngr } from "../tools/angr/index.js";
import {
  a64linkProgram,
  ARCH,
  crosslinkProgram,
  linkProgram,
  type LinkOutcome,
  winlinkProgram,
} from "../tools/vex/index.js";
import { ghidraPreludeFlags } from "../verify/recompile/ghidra-prelude.js";
import { isRewriteValue } from "../verify/recompile/rewrite-value.js";
import { binaryToolchain } from "./detect-toolchain.js";

/**
 * Where a linked program maps the image: a position-independent one (the graph has it at 0) at 0x10000000, since
 * Linux keeps the first 64 KiB and a small program's code lies there; a fixed-address one where it says.
 */
export function linkBase(path: string): number {
  const header = Buffer.alloc(18);
  const fd = openSync(path, "r");
  try {
    readSync(fd, header, 0, 18, 0);
  } finally {
    closeSync(fd);
  }
  if (header.readUInt32BE(0) !== 0x7f454c46) return 0;
  // e_type in the file's own byte order (EI_DATA: 1 little-endian, 2 big-endian); ET_DYN is 3.
  const type = header[5] === 2 ? header.readUInt16BE(16) : header.readUInt16LE(16);
  return type === 3 ? 0x10000000 : 0;
}

export async function linkBinary(
  store: GraphStore,
  binary: string,
  path: string,
  dir: string,
  translated: number[],
): Promise<LinkOutcome> {
  const architecture = store.getNode(binary)?.architecture;
  if (architecture === "arm-v5te" || architecture === "arm-v6k" || architecture === "arm-v7") {
    return crosslink(store, binary, path, dir, translated, architecture);
  }
  if (architecture === "arm64" && !isPe(path)) {
    // A shared library (an Android app's .so) becomes a host library named as the original, its exports kept.
    const library = isElfLibrary(path);
    const outcome = await a64linkProgram(locateAngr(), {
      binary: resolve(path),
      lifted: [join(dir, "lifted.c")],
      translated,
      out: join(dir, library ? libraryName(store.getNode(binary)?.label, path) : "program"),
      base: linkBase(path),
    });
    const kept = verifiedRewrites(
      store,
      binary,
      "a rewrite verified for the guest's CPU is not linked into a program for another CPU",
    );
    return {
      executable: outcome.executable,
      imports: outcome.imports,
      rewrites: 0,
      rewrites_skipped: kept,
      ...(library ? { library: true } : {}),
    };
  }
  if (architecture === "x86_64" && isPe(path)) {
    const outcome = await winlinkProgram(locateAngr(), {
      binary: resolve(path),
      lifted: [join(dir, "lifted.c")],
      translated,
      out: join(dir, "program"),
    });
    const kept = verifiedRewrites(
      store,
      binary,
      "a rewrite verified for Windows' calling convention is not linked into a Linux program",
    );
    return {
      executable: outcome.executable,
      imports: outcome.imports,
      rewrites: 0,
      rewrites_skipped: kept,
      unserved: outcome.unserved,
    };
  }
  if (architecture !== "x86_64") {
    throw new Error(
      "linking covers x86-64 Linux and Windows programs, and 32-bit ARM and AArch64 Linux ones as guests, on an x86-64 host for now",
    );
  }
  const toolchain = binaryToolchain(store, binary);
  const functions: Record<string, number> = {};
  const rewrites: { address: number; name: string; source: string; flags: string[] }[] = [];
  const unusable: { address: number; reason: string }[] = [];
  for (const fn of store.nodesOfKind("function")) {
    if (fn.binary !== binary || fn.address === undefined) continue;
    const address = Number(BigInt(fn.address));
    if (fn.label !== undefined) functions[fn.label] = address;
    for (const h of store.hypothesesFor(fn.id, "name")) {
      if (h.confidence !== "rejected" && typeof h.value === "string") functions[h.value] ??= address;
    }
    const verified = store
      .hypothesesFor(fn.id, "rewrite")
      .find((h) => h.confidence === "verified" && isRewriteValue(h.value) && h.value.last === undefined);
    if (verified !== undefined && toolchain === undefined) {
      // Compiled as it was verified, or not at all: without the toolchain it stays a translation.
      unusable.push({ address, reason: "no detected toolchain to compile it with (atlas detect toolchain)" });
    } else if (verified !== undefined && isRewriteValue(verified.value) && toolchain !== undefined) {
      const flags = [...toolchain.flags, "-w", ...(verified.value.prelude === "ghidra" ? ghidraPreludeFlags() : [])];
      rewrites.push({ address, name: verified.value.name, source: verified.value.source, flags });
    }
  }
  const outcome = await linkProgram(locateAngr(), {
    // Absolute: the program reads the original's segments from it when it starts, wherever it is run from.
    binary: resolve(path),
    lifted: [join(dir, "lifted.c")],
    translated,
    out: join(dir, "program"),
    rewrites,
    functions,
    base: linkBase(path),
  });
  return { ...outcome, rewrites_skipped: [...unusable, ...outcome.rewrites_skipped] };
}

/**
 * A 32-bit ARM program for this host: its translations with its system calls emulated (crosslink.py). Verified
 * rewrites are C verified for the guest's CPU and ABI, so they cannot stand in for translations in a host program:
 * each is reported as kept a translation.
 */
async function crosslink(
  store: GraphStore,
  binary: string,
  path: string,
  dir: string,
  translated: number[],
  architecture: "arm-v5te" | "arm-v6k" | "arm-v7",
): Promise<LinkOutcome> {
  const kept = verifiedRewrites(
    store,
    binary,
    "a rewrite verified for the guest's CPU is not linked into a program for another CPU",
  );
  const outcome = await crosslinkProgram(locateAngr(), {
    arch: ARCH[architecture].name,
    endness: ARCH[architecture].endness,
    // Absolute: the program reads the original's segments from it when it starts, wherever it is run from.
    binary: resolve(path),
    lifted: [join(dir, "lifted.c")],
    translated,
    out: join(dir, "program"),
    base: linkBase(path),
  });
  return { executable: outcome.executable, imports: 0, rewrites: 0, rewrites_skipped: kept };
}

/** The functions of the binary with a verified rewrite, each with why it stays a translation. */
function verifiedRewrites(store: GraphStore, binary: string, reason: string): { address: number; reason: string }[] {
  const kept: { address: number; reason: string }[] = [];
  for (const fn of store.nodesOfKind("function")) {
    if (fn.binary !== binary || fn.address === undefined) continue;
    if (store.hypothesesFor(fn.id, "rewrite").some((h) => h.confidence === "verified")) {
      kept.push({ address: Number(BigInt(fn.address)), reason });
    }
  }
  return kept;
}

/** Whether the file is a PE image (MZ header pointing at a PE signature). */
function isPe(path: string): boolean {
  const header = Buffer.alloc(0x40);
  const fd = openSync(path, "r");
  try {
    if (readSync(fd, header, 0, 0x40, 0) < 0x40 || header.readUInt16LE(0) !== 0x5a4d) return false;
    const signature = Buffer.alloc(4);
    return readSync(fd, signature, 0, 4, header.readUInt32LE(0x3c)) === 4 && signature.readUInt32LE(0) === 0x4550;
  } finally {
    closeSync(fd);
  }
}

/** Whether a 64-bit little-endian ELF is a shared library: no PT_INTERP program header (nothing loads it as a program). */
function isElfLibrary(path: string): boolean {
  const fd = openSync(path, "r");
  try {
    const header = Buffer.alloc(64);
    if (readSync(fd, header, 0, 64, 0) < 64 || header.readUInt32BE(0) !== 0x7f454c46 || header[4] !== 2) return false;
    const at = Number(header.readBigUInt64LE(0x20));
    const size = header.readUInt16LE(0x36);
    const count = header.readUInt16LE(0x38);
    const table = Buffer.alloc(size * count);
    readSync(fd, table, 0, table.length, at);
    for (let k = 0; k < count; k++) if (table.readUInt32LE(k * size) === 3) return false; // PT_INTERP
    return true;
  } finally {
    closeSync(fd);
  }
}

/**
 * A library's file name: the last part of the binary's label (an .apk's "lua.apk:lib/arm64-v8a/liblua.so" gives
 * liblua.so; the file itself is then a temporary extract), else the file's own name.
 */
function libraryName(label: string | undefined, path: string): string {
  const last = label?.split(/[/:]/).pop();
  return last !== undefined && last !== "" ? last : basename(path);
}
