# Dependency reviews

One entry per dependency that runs code on the operator's machine beyond a plain library: what was checked, the
verdict and the conditions of use. Repeat the review before every version bump, and add the new entry above the old.

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
