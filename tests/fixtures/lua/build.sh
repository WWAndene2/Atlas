#!/usr/bin/env bash
# Builds the Lua ground-truth fixture: one compile of Lua's interpreter, kept twice.
#
#   build/lua.symbols   with symbols and DWARF: the answer key
#   build/lua.stripped  the same file with every symbol removed: what the engines analyse
#
# The stripped file is made from the symbol build by `strip`, not by a second compile, so its code is byte for byte
# the same and every address in the answer key holds in it. The source is a pinned release, checked by SHA-256
# against the value lua.org publishes. Lua is MIT-licensed, so the fixture may be redistributed; the output is still
# kept out of git (.gitignore) because it depends on the local compiler.
#
# Idempotent: with both outputs present, a second run does nothing. Needs curl, tar, make, cc, strip, sha256sum.
set -euo pipefail

LUA_VERSION="5.4.7"
LUA_SHA256="9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30"
# -O2 comes from Lua's own makefile. -g for the answer key; LTO off so functions are not merged across files.
EXTRA_CFLAGS="-g -fno-lto"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/build"
symbols="$out/lua.symbols"
stripped="$out/lua.stripped"

if [[ -x "$symbols" && -x "$stripped" ]]; then
  echo "Lua fixture already built in $out"
  exit 0
fi

for tool in curl tar make cc strip sha256sum; do
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
make -s -C "$work/lua-$LUA_VERSION/src" linux MYCFLAGS="$EXTRA_CFLAGS" >/dev/null

mkdir -p "$out"
cp "$work/lua-$LUA_VERSION/src/lua" "$symbols"
strip --strip-all -o "$stripped" "$symbols"
echo "Lua $LUA_VERSION fixture built in $out"
