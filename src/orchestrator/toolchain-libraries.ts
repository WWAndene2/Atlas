// The static libraries a toolchain links by default, found by asking the compiler (-print-file-name) with the
// binary's detected flags, so a multilib toolchain answers for the right CPU and float ABI.
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import type { Toolchain } from "../verify/recompile/recompile-check.js";

const NAMES = ["libgcc.a", "libc.a", "libm.a", "libmingwex.a", "libmsvcrt.a", "libmingw32.a"];

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
