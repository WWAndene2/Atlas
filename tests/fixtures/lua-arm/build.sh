#!/usr/bin/env bash
# Builds the ARM ground-truth fixture: Lua's interpreter for the CPU of the Nintendo 3DS (ARM11 MPCore: ARMv6K, hard
# float, ARM mode), with the toolchain family 3DS homebrew uses (GCC for arm-none-eabi with newlib), linked at
# 0x100000 like a 3DS application's code. One link, kept twice:
#
#   build/lua.elf   with symbols and DWARF: the answer key
#   build/lua.bin   the loaded image as raw bytes, no header and no symbol: the shape of a 3DS code.bin, where
#                   nothing tells the engine the CPU, the load address or where functions are
#
# lua.bin is made from lua.elf by objcopy, so every address in the key holds in it at base 0x100000. Same pinned and
# SHA-256-checked Lua release as tests/fixtures/lua. Output kept out of git. Idempotent.
# Needs curl, tar, sha256sum and arm-none-eabi-gcc with newlib (apt install gcc-arm-none-eabi libnewlib-arm-none-eabi).
set -euo pipefail

LUA_VERSION="5.4.7"
LUA_SHA256="9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30"
BASE="0x100000"
CFLAGS=(-O2 -g -marm -march=armv6k+fp -mtune=mpcore -mfloat-abi=hard -mtp=soft -std=gnu99)

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/build"
if [[ -f "$out/lua.elf" && -f "$out/lua.bin" ]]; then
  echo "Lua ARM fixture already built in $out"
  exit 0
fi
for tool in curl tar sha256sum arm-none-eabi-gcc arm-none-eabi-objcopy; do
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

# luac.c is the separate compiler program; everything else is the interpreter. newlib's nosys stubs stand in for the
# operating system: the fixture is analysed, never run, and the linker's "not implemented" notes about them are noise.
mapfile -t sources < <(cd "$src" && ls ./*.c | grep -v '/luac\.c$')
(cd "$src" && arm-none-eabi-gcc "${CFLAGS[@]}" -o lua.elf "${sources[@]}" -lm -specs=nosys.specs \
  -Wl,-Ttext-segment="$BASE" 2>/dev/null)

mkdir -p "$out"
cp "$src/lua.elf" "$out/lua.elf"
arm-none-eabi-objcopy -O binary "$out/lua.elf" "$out/lua.bin"
echo "Lua $LUA_VERSION ARM fixture built in $out"
