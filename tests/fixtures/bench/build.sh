#!/usr/bin/env bash
# Builds the rewrite benchmark (bench.c, written for Atlas): x86-64 Linux, GCC at -O2, kept stripped (what Atlas
# analyses) and unstripped (the answer key). Output kept out of git. Idempotent.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/build"
if [[ -f "$out/bench.stripped" && -f "$out/bench.symbols" ]]; then
  echo "benchmark already built in $out"
  exit 0
fi
mkdir -p "$out"
gcc -std=gnu11 -O2 -g -o "$out/bench.symbols" "$here/bench.c" -lm
strip --strip-all -o "$out/bench.stripped" "$out/bench.symbols"
echo "benchmark built in $out"
