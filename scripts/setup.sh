#!/usr/bin/env bash
# Sets up Atlas in one command: its Node dependencies and build, Java, Ghidra, the Lua ground-truth fixture and an
# `atlas` command. Checks each part, says what is missing and how to get it, and exits non-zero if a required part
# is missing. Idempotent: what is already in place is checked and left alone.
#
# Engines go in the tools directory, $ATLAS_TOOLS_DIR or ${XDG_DATA_HOME:-~/.local/share}/atlas/tools, where Atlas
# looks for them (src/tools/tools-dir.ts holds the same rule). Ghidra is installed as its review requires
# (docs/DEPENDENCY_REVIEWS.md): exactly 12.1.4, archive checked against the published SHA-256 before unpacking.
set -euo pipefail

GHIDRA_VERSION="12.1.4"
GHIDRA_ARCHIVE="ghidra_${GHIDRA_VERSION}_PUBLIC_20260921.zip"
GHIDRA_SHA256="ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ARCHIVE}"
JAVA_MIN=21
NODE_MIN="22.13"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tools="${ATLAS_TOOLS_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/atlas/tools}"
ghidra="$tools/ghidra_${GHIDRA_VERSION}_PUBLIC"
missing=()

step() { printf '\n== %s\n' "$1"; }
ok() { printf '   ok: %s\n' "$1"; }
lack() {
  printf '   MISSING: %s\n   how: %s\n' "$1" "$2"
  missing+=("$1")
}
have() { command -v "$1" >/dev/null 2>&1; }
version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }
as_root() { if [[ $(id -u) -eq 0 ]]; then "$@"; elif have sudo; then sudo -n "$@"; else return 1; fi; }

step "Node.js >= $NODE_MIN"
if have node && version_ge "$(node -p process.versions.node)" "$NODE_MIN"; then
  ok "node $(node -p process.versions.node)"
else
  lack "Node.js >= $NODE_MIN" "install it from https://nodejs.org or with nvm (nvm install 22), then run this again"
fi

if [[ ${#missing[@]} -eq 0 ]]; then
  step "Atlas: dependencies and build"
  cd "$repo"
  # npm ci only when the lock file is newer than the installed tree: a second run installs nothing.
  if [[ ! -f node_modules/.package-lock.json || package-lock.json -nt node_modules/.package-lock.json ]]; then
    npm ci --no-audit --no-fund --loglevel=error
  fi
  npm run --silent build
  ok "built in $repo/dist"
fi

step "Java >= $JAVA_MIN (for Ghidra)"
java_major() { java -version 2>&1 | grep -m1 -oE 'version "[0-9]+' | grep -oE '[0-9]+$'; }
if ! { have java && [[ "$(java_major)" -ge $JAVA_MIN ]]; }; then
  if have apt-get && as_root apt-get install -y -qq "openjdk-${JAVA_MIN}-jdk-headless" >/dev/null 2>&1; then
    echo "   installed openjdk-${JAVA_MIN}-jdk-headless"
  fi
fi
if have java && [[ "$(java_major)" -ge $JAVA_MIN ]]; then
  ok "java $(java_major)"
else
  lack "Java >= $JAVA_MIN" "install a JDK $JAVA_MIN (apt install openjdk-${JAVA_MIN}-jdk-headless, or https://adoptium.net), then run this again"
fi

step "Ghidra $GHIDRA_VERSION"
if [[ -f "$ghidra/Ghidra/application.properties" ]] &&
  grep -qx "application.version=$GHIDRA_VERSION" "$ghidra/Ghidra/application.properties"; then
  ok "$ghidra"
elif ! { have curl && have sha256sum && { have unzip || have python3; }; }; then
  lack "Ghidra $GHIDRA_VERSION" "install curl, sha256sum and unzip, then run this again"
else
  mkdir -p "$tools"
  work="$(mktemp -d "$tools/.download.XXXXXX")"
  trap 'rm -rf "$work"' EXIT
  echo "   downloading $GHIDRA_ARCHIVE (about 570 MB)"
  if curl -sSfL -o "$work/$GHIDRA_ARCHIVE" "$GHIDRA_URL" &&
    echo "$GHIDRA_SHA256  $work/$GHIDRA_ARCHIVE" | sha256sum --check --quiet; then
    if have unzip; then unzip -q "$work/$GHIDRA_ARCHIVE" -d "$work"; else python3 -m zipfile -e "$work/$GHIDRA_ARCHIVE" "$work"; fi
    # Python's zipfile drops the executable bits; Ghidra's launchers and native tools need them.
    find "$work/ghidra_${GHIDRA_VERSION}_PUBLIC" -type f \( -path '*/support/*' -o -path '*/os/linux_*' -o -name 'ghidraRun' \) \
      -exec chmod +x {} +
    rm -rf "$ghidra"
    mv "$work/ghidra_${GHIDRA_VERSION}_PUBLIC" "$ghidra"
    ok "$ghidra"
  else
    lack "Ghidra $GHIDRA_VERSION" "download or checksum failed for $GHIDRA_URL; check the network and run this again"
  fi
  rm -rf "$work"
  trap - EXIT
fi

step "Lua ground-truth fixture"
if "$repo/tests/fixtures/lua/build.sh" | sed 's/^/   /'; then
  ok "$repo/tests/fixtures/lua/build"
else
  lack "Lua fixture" "install curl, make and a C compiler (apt install build-essential), then run this again"
fi

step "ARM ground-truth fixture (3DS-like raw image)"
if ! have arm-none-eabi-gcc && have apt-get; then
  as_root apt-get install -y -qq gcc-arm-none-eabi libnewlib-arm-none-eabi >/dev/null 2>&1 ||
    { as_root apt-get update -qq >/dev/null 2>&1 &&
      as_root apt-get install -y -qq gcc-arm-none-eabi libnewlib-arm-none-eabi >/dev/null 2>&1; } || true
fi
if "$repo/tests/fixtures/lua-arm/build.sh" | sed 's/^/   /'; then
  ok "$repo/tests/fixtures/lua-arm/build"
else
  lack "Lua ARM fixture" "apt install gcc-arm-none-eabi libnewlib-arm-none-eabi, then run this again"
fi

step "PC and mobile ground-truth fixtures (Windows program, Android package)"
if ! { have x86_64-w64-mingw32-gcc && have aarch64-linux-gnu-gcc && have zip; } && have apt-get; then
  as_root apt-get install -y -qq zip gcc-mingw-w64-x86-64 gcc-aarch64-linux-gnu >/dev/null 2>&1 ||
    { as_root apt-get update -qq >/dev/null 2>&1 &&
      as_root apt-get install -y -qq zip gcc-mingw-w64-x86-64 gcc-aarch64-linux-gnu >/dev/null 2>&1; } || true
fi
if "$repo/tests/fixtures/lua-platforms/build.sh" | sed 's/^/   /'; then
  ok "$repo/tests/fixtures/lua-platforms/build"
else
  lack "Lua platform fixtures" "apt install zip gcc-mingw-w64-x86-64 gcc-aarch64-linux-gnu, then run this again"
fi

step "Compilers for toolchain detection (more installed, more targets detected)"
# Detection can only find a compiler that is installed: several GCC and Clang releases, and cross compilers for the
# architectures Atlas names (32-bit Windows, ARM Linux, MIPS, PowerPC). Recommended, not required.
compilers=(gcc-9 gcc-10 gcc-11 gcc-12 gcc-14 clang-14 clang-15 clang-17 clang-19 gcc-mingw-w64-i686
  gcc-arm-linux-gnueabihf gcc-mips-linux-gnu gcc-mipsel-linux-gnu gcc-powerpc-linux-gnu gcc-powerpc64-linux-gnu
  gcc-11-aarch64-linux-gnu)
drivers=(gcc-9 gcc-10 gcc-11 gcc-12 gcc-14 clang-14 clang-15 clang-17 clang-19 i686-w64-mingw32-gcc
  arm-linux-gnueabihf-gcc mips-linux-gnu-gcc mipsel-linux-gnu-gcc powerpc-linux-gnu-gcc powerpc64-linux-gnu-gcc
  aarch64-linux-gnu-gcc-11)
absent=()
for d in "${drivers[@]}"; do have "$d" || absent+=("$d"); done
if [[ ${#absent[@]} -gt 0 ]] && have apt-get; then
  as_root apt-get install -y -qq "${compilers[@]}" >/dev/null 2>&1 ||
    { as_root apt-get update -qq >/dev/null 2>&1 && as_root apt-get install -y -qq "${compilers[@]}" >/dev/null 2>&1; } || true
  absent=()
  for d in "${drivers[@]}"; do have "$d" || absent+=("$d"); done
fi
if [[ ${#absent[@]} -eq 0 ]]; then
  ok "${#drivers[@]} compilers"
else
  printf '   note: not installed, so not detectable: %s\n   how: apt install %s\n' "${absent[*]}" "${compilers[*]}"
fi

step "Toolchain ground-truth fixtures (GCC 11, Clang 17, MIPS, PowerPC)"
if "$repo/tests/fixtures/lua-toolchains/build.sh" | sed 's/^/   /'; then
  ok "$repo/tests/fixtures/lua-toolchains/build"
else
  lack "Lua toolchain fixtures" "install the compilers above, then run this again"
fi

step "angr for the equivalence check (atlas verify --equivalence)"
# A Python environment of its own in the tools directory, exactly the reviewed version (docs/DEPENDENCY_REVIEWS.md),
# wheels only. Recommended, not required: without it --equivalence answers that angr is missing.
ANGR_VERSION=10.0.5
if [[ -x "$tools/py/bin/python" ]] && "$tools/py/bin/python" -c "import angr; assert angr.__version__ == '$ANGR_VERSION'" 2>/dev/null; then
  ok "angr $ANGR_VERSION"
elif have python3 && python3 -m venv "$tools/py" >/dev/null 2>&1 &&
  "$tools/py/bin/pip" install -q --only-binary=:all: "angr==$ANGR_VERSION" >/dev/null 2>&1; then
  ok "angr $ANGR_VERSION in $tools/py"
else
  printf '   note: angr not installed, so no equivalence check\n   how: apt install python3-venv, then run this again\n'
fi

step "atlas command"
launcher_dir="$HOME/.local/bin"
mkdir -p "$launcher_dir"
launcher="$launcher_dir/atlas"
cat >"$launcher.tmp" <<EOF
#!/usr/bin/env bash
# Written by $repo/scripts/setup.sh
exec node --disable-warning=ExperimentalWarning "$repo/dist/src/cli/main.js" "\$@"
EOF
chmod +x "$launcher.tmp"
# One launcher per user: a setup run in another checkout re-points it. Say so, so no one runs the wrong code unaware.
previous="$(grep -o '"[^"]*/dist/src/cli/main.js"' "$launcher" 2>/dev/null | tr -d '"' || true)"
if [[ -n "$previous" && "$previous" != "$repo/dist/src/cli/main.js" ]]; then
  echo "   note: atlas pointed to ${previous%/dist/src/cli/main.js}; it now runs $repo"
fi
mv "$launcher.tmp" "$launcher"
# The MCP server, for AI clients that connect rather than run commands (configure the client to start atlas-mcp).
cat >"$launcher_dir/atlas-mcp.tmp" <<EOF
#!/usr/bin/env bash
# Written by $repo/scripts/setup.sh
exec node --disable-warning=ExperimentalWarning "$repo/dist/src/mcp/server.js" "\$@"
EOF
chmod +x "$launcher_dir/atlas-mcp.tmp"
mv "$launcher_dir/atlas-mcp.tmp" "$launcher_dir/atlas-mcp"
if [[ ":$PATH:" == *":$launcher_dir:"* ]]; then
  ok "atlas and atlas-mcp ($launcher_dir)"
else
  ok "$launcher and atlas-mcp (not on PATH: add $launcher_dir to PATH, or call them by their full path)"
fi

step "Summary"
if [[ ${#missing[@]} -eq 0 ]]; then
  echo "   Atlas is ready. Try: atlas load $repo/tests/fixtures/lua/build/lua.stripped && atlas list functions --json"
else
  printf '   missing: %s\n' "${missing[@]}"
  exit 1
fi
