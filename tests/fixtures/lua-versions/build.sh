#!/usr/bin/env bash
# Builds the previous Lua release (5.4.6) the way tests/fixtures/lua builds 5.4.7, with symbols and DWARF, as the
# documented build knowledge is carried over from (atlas match graph, M7): its graph names 5.4.7's stripped one.
#
#   build/lua-5.4.6.symbols
#
# The source is a pinned release, checked by SHA-256 against the value lua.org publishes. MIT-licensed; the output is
# kept out of git since it depends on the local compiler. Idempotent. Needs curl, tar, make, cc, sha256sum.
set -euo pipefail

LUA_VERSION="5.4.6"
LUA_SHA256="7d5ea1b9cb6aa0b59ca3dde1c6adcb57ef83a1ba8e5432c0ecd06bf439b3ad88"
EXTRA_CFLAGS="-g -fno-lto"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/build"
symbols="$out/lua-$LUA_VERSION.symbols"

if [[ -x "$symbols" ]]; then
  echo "Lua $LUA_VERSION fixture already built in $out"
  exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tarball="$work/lua-$LUA_VERSION.tar.gz"
curl -sSfL -o "$tarball" "https://www.lua.org/ftp/lua-$LUA_VERSION.tar.gz"
echo "$LUA_SHA256  $tarball" | sha256sum --check --quiet
tar -xzf "$tarball" -C "$work"
make -s -C "$work/lua-$LUA_VERSION/src" linux MYCFLAGS="$EXTRA_CFLAGS" >/dev/null
mkdir -p "$out"
cp "$work/lua-$LUA_VERSION/src/lua" "$symbols"
echo "built $symbols"
