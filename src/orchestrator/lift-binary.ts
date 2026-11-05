// The "it runs" path of recompilation: every function of a binary translated mechanically to C (src/tools/vex/),
// written as a C project next to the runtime, with a dispatch table from guest addresses to translations. It
// recompiles a whole program before any function is rewritten by hand; a verified rewrite then takes its
// function's place in the dispatch (the source path, byte-exact). Functions the translator does not handle are
// listed with the reason, so the gaps are counted, not guessed.
import { copyFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { GraphStore } from "../graph/index.js";
import { locateAngr } from "../tools/angr/index.js";
import { bigEndian, liftFunctions, RUNTIME_HEADER } from "../tools/vex/index.js";

export interface LiftOutcome {
  binary: string;
  functions: number;
  translated: number;
  /** Reason (addresses blanked) to the number of functions it stopped. */
  unsupported: Record<string, number>;
  files: string[];
}

export async function liftBinary(store: GraphStore, binary: string, out: string, path?: string): Promise<LiftOutcome> {
  const node = store.getNode(binary);
  if (node?.architecture === undefined) throw new Error(`${binary} has no recorded architecture`);
  const functions = store
    .nodesOfKind("function")
    .filter((f) => f.binary === binary && f.code !== undefined && f.address !== undefined && f.thunk !== true)
    .map((f) => ({ address: Number(BigInt(f.address as string)), code: f.code as string }));
  const lifted = await liftFunctions(locateAngr(), node.architecture, functions, path);
  const translated = lifted.filter((l): l is { address: string; c: string } => "c" in l);
  const unsupported: Record<string, number> = {};
  for (const l of lifted) {
    if ("unsupported" in l) {
      const reason = l.unsupported.replace(/0x[0-9a-f]+/g, "X");
      unsupported[reason] = (unsupported[reason] ?? 0) + 1;
    }
  }
  await mkdir(out, { recursive: true });
  const prefix = bigEndian(node.architecture) ? "#define ATLAS_BIG_ENDIAN\n" : "";
  await writeFile(
    join(out, "lifted.c"),
    `${prefix}#include "atlas_lift.h"\n\n${translated.map((t) => t.c).join("\n")}`,
  );
  const names = translated.map((t) => `fn_${BigInt(t.address).toString(16)}`);
  await writeFile(
    join(out, "dispatch.c"),
    `${prefix}#include "atlas_lift.h"\n${names.map((n) => `void ${n}(atlas_state *s);`).join("\n")}\n\n` +
      "/* Called for a guest address no translation covers: the program decides (an import, a gap). */\n" +
      "void atlas_missing(atlas_state *s, uint64_t target);\n\n" +
      "void atlas_call(atlas_state *s, uint64_t target) {\n  switch (target) {\n" +
      translated.map((t, i) => `    case ${t.address}ULL: ${names[i]}(s); return;`).join("\n") +
      "\n    default: atlas_missing(s, target);\n  }\n}\n",
  );
  await copyFile(RUNTIME_HEADER, join(out, "atlas_lift.h"));
  const report = { binary, functions: functions.length, translated: translated.length, unsupported };
  await writeFile(join(out, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  return { ...report, files: ["lifted.c", "dispatch.c", "atlas_lift.h", "report.json"].map((f) => join(out, f)) };
}
