#!/usr/bin/env bash
# Builds the PC and mobile ground-truth fixtures: Lua's interpreter as a Windows program and as an Android-style
# native library, each kept with its answer key.
#
#   build/lua.exe          Windows x86-64 PE (MinGW-w64 GCC), stripped: what the engines analyse
#   build/lua.exe.debug    the same link unstripped: the answer key (its COFF symbol table lists static functions
#                          too, which a linker map leaves out)
#   build/liblua.so        Linux/Android-style AArch64 shared library (GCC), stripped of its local symbols
#   build/liblua.so.debug  the same library unstripped: the answer key
#   build/lua.apk          a ZIP package holding lib/arm64-v8a/liblua.so, as an Android package does
#
# Same pinned and SHA-256-checked Lua release as tests/fixtures/lua. Output kept out of git. Idempotent.
# Needs curl, tar, sha256sum, zip, x86_64-w64-mingw32-gcc and aarch64-linux-gnu-gcc
# (apt install zip gcc-mingw-w64-x86-64 gcc-aarch64-linux-gnu).
set -euo pipefail

LUA_VERSION="5.4.7"
LUA_SHA256="9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/build"
if [[ -f "$out/lua.exe" && -f "$out/lua.exe.debug" && -f "$out/liblua.so" && -f "$out/liblua.so.debug" && -f "$out/lua.apk" ]]; then
  echo "Lua platform fixtures already built in $out"
  exit 0
fi
for tool in curl tar sha256sum zip x86_64-w64-mingw32-gcc x86_64-w64-mingw32-strip aarch64-linux-gnu-gcc \
  aarch64-linux-gnu-strip; do
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
mapfile -t library < <(cd "$src" && ls ./*.c | grep -vE '/luac?\.c$')
mkdir -p "$out"

# Windows: one link kept unstripped, then stripped by strip, so the code is the same in both.
(cd "$src" && x86_64-w64-mingw32-gcc -O2 -o "$out/lua.exe.debug" "${interpreter[@]}")
x86_64-w64-mingw32-strip --strip-all -o "$out/lua.exe" "$out/lua.exe.debug"

# Android-style library: position-independent AArch64 code exporting Lua's C API, as a game's native library would.
(cd "$src" && aarch64-linux-gnu-gcc -O2 -g -fPIC -shared -DLUA_USE_LINUX -o "$out/liblua.so.debug" "${library[@]}")
aarch64-linux-gnu-strip --strip-unneeded -o "$out/liblua.so" "$out/liblua.so.debug"
mkdir -p "$work/apk/lib/arm64-v8a"
cp "$out/liblua.so" "$work/apk/lib/arm64-v8a/"
printf '<manifest package="org.lua.fixture"/>\n' >"$work/apk/AndroidManifest.xml"
rm -f "$out/lua.apk"
(cd "$work/apk" && zip -qr "$out/lua.apk" AndroidManifest.xml lib)
echo "Lua platform fixtures built in $out"
