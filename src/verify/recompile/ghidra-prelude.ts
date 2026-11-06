// The flags that compile Ghidra-typed C (a rewrite with prelude "ghidra"): its types header, and four diagnostics
// kept as warnings. Ghidra's C calls functions it does not declare and mixes integer and pointer types; GCC 14 and
// Clang 16 made those errors. They are diagnostics only, so generated code is unchanged. Without them, newer compilers
// failed to compile most of Ghidra's C and toolchain detection ruled them out (Clang 17 Lua, measured). Each flag is
// known to every compiler release in view (-Wno-error=return-mismatch is not: GCC 13 and older refuse it).
import { repositoryPath } from "../../graph/index.js";

export function ghidraPreludeFlags(): string[] {
  return [
    "-include",
    repositoryPath("src", "verify", "recompile", "ghidra-types.h"),
    "-Wno-error=implicit-function-declaration",
    "-Wno-error=implicit-int",
    "-Wno-error=int-conversion",
    "-Wno-error=incompatible-pointer-types",
  ];
}
