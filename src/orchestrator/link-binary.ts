// The "it runs" path's last step: a binary's translations (lift-binary.ts) linked into a program, with every
// verified rewrite taking its translation's place where it can (src/tools/vex/rewrites.py says why not). The
// rewrites are compiled as they were verified: the binary's detected toolchain, Ghidra's prelude when they use it.
import { join, resolve } from "node:path";
import type { GraphStore } from "../graph/index.js";
import { locateAngr } from "../tools/angr/index.js";
import { linkProgram, type LinkOutcome } from "../tools/vex/index.js";
import { ghidraPreludeFlags } from "../verify/recompile/ghidra-prelude.js";
import { isRewriteValue } from "../verify/recompile/rewrite-value.js";
import { binaryToolchain } from "./detect-toolchain.js";

export async function linkBinary(
  store: GraphStore,
  binary: string,
  path: string,
  dir: string,
  translated: number[],
): Promise<LinkOutcome> {
  if (store.getNode(binary)?.architecture !== "x86_64") {
    throw new Error("linking covers x86-64 programs on an x86-64 host for now");
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
  });
  return { ...outcome, rewrites_skipped: [...unusable, ...outcome.rewrites_skipped] };
}
