#!/usr/bin/env bash
# Builds Lua with compilers and levels other than the defaults, to measure toolchain detection on targets whose
# toolchain is known to us but not given to Atlas. Each build is kept stripped (what Atlas analyses) and unstripped
# (the answer key):
#
#   build/gcc11-O2.{stripped,symbols}        x86-64, GCC 11 at -O2: an older compiler, named in the file's clue
#   build/clang17-O1.{stripped,symbols}      x86-64, Clang 17 at -O1, version string removed: no clue at all
#   build/mipsel-O2.{stripped,symbols}       little-endian MIPS (the PlayStation family's CPU), GCC at -O2
#   build/ppc-Os.{stripped,symbols}          32-bit big-endian PowerPC (GameCube and Wii's family), GCC at -Os
#
# Same pinned and SHA-256-checked Lua release as tests/fixtures/lua. Output kept out of git. Idempotent.
# Needs gcc-11, clang-17, mipsel-linux-gnu-gcc and powerpc-linux-gnu-gcc (scripts/setup.sh installs them).
set -euo pipefail

LUA_VERSION="5.4.7"
LUA_SHA256="9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/build"
builds=(gcc11-O2 clang17-O1 mipsel-O2 ppc-Os)
done_all=true
for b in "${builds[@]}"; do [[ -f "$out/$b.stripped" && -f "$out/$b.symbols" ]] || done_all=false; done
if $done_all; then
  echo "Lua toolchain fixtures already built in $out"
  exit 0
fi
for tool in curl tar sha256sum gcc-11 clang-17 mipsel-linux-gnu-gcc powerpc-linux-gnu-gcc; do
  command -v "$tool" >/dev/null || {
    echo "missing tool: $tool" >&2
    exit 1
  }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tarball="$work/lua-$LUA_VERSION.tar.gz"
curl -sSfL -o "$tarball" "https://www.lua.org/ftp/lua-$LUA_VERSION.tar.gz"
echo "$LUA_SHA256  $tarball" | sha256sum --check --quiet
tar -xzf "$tarball" -C "$work"
src="$work/lua-$LUA_VERSION/src"
mapfile -t interpreter < <(cd "$src" && ls ./*.c | grep -v '/luac\.c$')
mkdir -p "$out"

build() { # name, compiler, strip tool, flags...
  local name="$1" cc="$2" strip="$3"
  shift 3
  (cd "$src" && "$cc" -std=gnu99 "$@" -DLUA_COMPAT_5_3 -o "$out/$name.symbols" "${interpreter[@]}" -lm)
  "$strip" --strip-all -o "$out/$name.stripped" "$out/$name.symbols"
}
build gcc11-O2 gcc-11 strip -O2 -DLUA_USE_LINUX
build clang17-O1 clang-17 strip -O1 -DLUA_USE_LINUX
# No clue for this one: the compiler's version string (.comment) is removed, as some build pipelines do.
strip --remove-section=.comment "$out/clang17-O1.stripped"
build mipsel-O2 mipsel-linux-gnu-gcc mipsel-linux-gnu-strip -O2
build ppc-Os powerpc-linux-gnu-gcc powerpc-linux-gnu-strip -Os
echo "Lua toolchain fixtures built in $out"
