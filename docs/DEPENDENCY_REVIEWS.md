# Dependency reviews

One entry per dependency that runs code on the operator's machine beyond a plain library: what was checked, the
verdict and the conditions of use. Repeat the review before every version bump, and add the new entry above the old.

## Ghidra 12.1.4 — 4 November 2026

**Choice of version.** 12.1.4 (release of 21 September 2026), the latest patch of the 12.1 line, over the newer
12.2 (16 October 2026): 12.2 requires Java 25, which Ubuntu 24.04's packages do not provide, while 12.1.4 runs on
Java 21, the LTS release the distributions ship. A move to 12.2 or later waits until Java 25 is as easy to install,
and repeats this review.

**Scope of the check.** The release archive `ghidra_12.1.4_PUBLIC_20260921.zip` (569 MB unpacked to about 880 MB)
from the project's GitHub release, SHA-256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`,
equal to the value published on the release page. Read: the launch scripts and launch properties, the native
binaries, the bundled extensions, the licences. Run: headless analysis of the Lua fixture, also in a network
namespace with no network at all.

**Seen:**

- Apache 2.0, from the NSA's public repository; maintained by a team, regular releases. Atlas runs it as a separate
  program and does not ship it, so its licence sits beside MIT without conflict. The GNU demangler binaries it
  bundles (`GPL/`) are GPL and run as separate processes.
- Native binaries for Linux x86-64: the decompiler (`decompile`, `sleigh`), `lzfse` and the GNU demangler; the rest
  is Java (202 jars).
- Headless analysis of Lua gives the same result with no network, so it needs none. No telemetry found in the launch
  scripts or properties.
- Bundled extensions (Jython, machine learning, BSim and others) are archives, inactive unless installed; Atlas
  installs none.
- Headless mode compiles and runs Java scripts from the script path it is given: Atlas passes only its own
  `src/tools/ghidra/scripts/`.

**Not checked:** the Java code and native binaries line by line; the bundled third-party jars.

**Verdict:** usable as Atlas's first engine, under these conditions:

1. Exactly 12.1.4, archive checked against the SHA-256 above before unpacking. `locateGhidra` refuses any other
   version.
2. Java 21 from the system's packages.
3. No extensions installed; scripts only from `src/tools/ghidra/scripts/`.
4. Each run in a fresh temporary project, deleted afterwards (`-deleteProject`): no state carried between targets.

## REA (`rea-agents`) 6.8.0 — 4 November 2026

**Scope of the check.** The npm tarball (`rea-agents-6.8.0.tgz`, integrity
`sha512-9QDeRnGqEDzABZyr04eLnBXBv/c6I9/TWu/6M0MD4pEfkySI/BIgwTODIbAReX3C1x6hjw9+Jlx4A2yUSPZ9ww==`) was unpacked and
read, never run: package scripts, install hooks, bundled binaries, network calls and external addresses, by search
over its 2,398 files (compiled JavaScript). Not a line-by-line audit.

**Seen:**

- No install hook (`preinstall`, `install`, `postinstall`). `prepare` acts only in REA's own source checkout.
- No telemetry or reporting service found; external addresses are GitHub, Hopper's site, documentation and test
  placeholders. The HTTP server is opt-in (`--http`); the default transport is stdio.
- MIT licence. Single maintainer. 53 MB, 43 direct dependencies (among them Playwright, node-pty with native code,
  isomorphic-git, openpgp), most of them unused by Atlas.
- Optional dependency Frida 17.23.2 runs an install script that downloads a prebuilt binary.
- A prebuilt Windows binary (`native/windows/build/rea-windows-x64.node`) that cannot be audited; unused on Linux.
- REA's `install.sh` installs the latest release from GitHub, not a fixed version.

**Not checked:** the dependencies' own code; runtime behaviour; the GitHub popularity figures (430k stars shown,
implausible for the project, so given no weight).

**Verdict:** usable as Atlas's second engine, under these conditions:

1. Installed at exactly 6.8.0, integrity checked, with `--ignore-scripts --omit=optional` (nothing runs at
   install, no Frida). Never through REA's `install.sh`.
2. Started only by `src/tools/rea/`, over stdio, never with `--http`.
3. Atlas works without it: Ghidra headless is the first engine.

## angr 10.0.5 (with z3-solver 5.3.1) — 5 November 2026

**Scope of the check.** Installed from PyPI wheels only (`--only-binary=:all:`, no source build, no install script)
into a Python environment of its own in the tools directory. The installed tree was inspected: 43 packages, 63
native shared objects (among them Z3 and pyvex/VEX), about 500 MB. Not a line-by-line audit.

**Seen:** BSD-2-Clause (angr, claripy, pyvex, cle, archinfo), MIT (Z3); Atlas runs `equivalence.py` as a
subprocess and links none of it. No
network use at run time found.

**Conditions:**

1. Exactly 10.0.5, installed by `scripts/setup.sh` from wheels; a bump needs a new entry.
2. Run only as a subprocess on machine code Atlas extracted itself; target code is executed symbolically, never
   natively.
3. Opt-in (`atlas verify --equivalence`): nothing else depends on it.

## Rizin 0.9.1 — 5 November 2026

**Scope of the check.** The release's static Linux x86-64 archive (`rizin-v0.9.1-static-x86_64.tar.xz`, SHA-256
`9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf`) from the project's GitHub releases. The release publishes no checksum: the hash was recorded at the first
download (trust on first use), approved by the operator. Run on
Atlas's fixtures; its code was not audited.

**Seen:** LGPL-3.0, run as a separate program (no linking into Atlas). A self-contained binary with its plugins
built in; no network use seen in the analysis commands Atlas runs (`aaa`, `aflj`).

**Conditions:**

1. Exactly 0.9.1, installed by `scripts/setup.sh` only after the SHA-256 above matches; a bump needs a new entry.
2. Run with `-N` (no user scripts or plugins) and only the analysis commands in `src/tools/rizin/`; never `-d`
   (debugging runs the target).
