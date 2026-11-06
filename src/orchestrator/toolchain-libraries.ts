// The static libraries a toolchain links by default, found by asking the compiler (-print-file-name) with the
// binary's detected flags, so a multilib toolchain answers for the right CPU and float ABI.
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import type { Toolchain } from "../verify/recompile/recompile-check.js";

// The libraries linked by default, and the startup objects the linker adds to every program (_start, the
// constructor and destructor walkers, register_tm_clones...): code of the toolchain, not of the program. Without the
// startup objects, subagents rewrote _start in assembly in the benchmark run.
const NAMES = [
  "libgcc.a",
  "libc.a",
  "libm.a",
  "libmingwex.a",
  "libmsvcrt.a",
  "libmingw32.a",
  "crt1.o",
  "Scrt1.o",
  "crti.o",
  "crtn.o",
  "crtbegin.o",
  "crtbeginS.o",
  "crtend.o",
  "crtendS.o",
  "crt2.o",
];

export function toolchainLibraries(toolchain: Toolchain): string[] {
  const found: string[] = [];
  for (const name of NAMES) {
    try {
      const path = execFileSync(toolchain.cc, [...toolchain.flags, `-print-file-name=${name}`], {
        encoding: "utf8",
      }).trim();
      // The compiler echoes the bare name when it has no such file.
      if (path !== name && existsSync(path)) found.push(path);
    } catch {
      // A compiler that cannot answer has no default libraries to offer.
    }
  }
  return found;
}
