import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  GHIDRA_VERSION,
  GhidraUnavailableError,
  analyseWithGhidra,
  locateGhidra,
} from "../../../src/tools/ghidra/index.js";

const lua = fileURLToPath(new URL("../../fixtures/lua/build/", import.meta.url));
const ghidraAvailable = ((): boolean => {
  try {
    locateGhidra();
    return true;
  } catch {
    return false;
  }
})();
const runnable = ghidraAvailable && existsSync(join(lua, "lua.stripped"));

function fakeInstall(version: string): string {
  const dir = mkdtempSync(join(tmpdir(), "atlas-fake-ghidra-"));
  mkdirSync(join(dir, "support"));
  mkdirSync(join(dir, "Ghidra"));
  writeFileSync(join(dir, "support", "analyzeHeadless"), "");
  writeFileSync(join(dir, "Ghidra", "application.properties"), `application.version=${version}\n`);
  return dir;
}

describe("locateGhidra", () => {
  it("names what is missing when Ghidra is not configured", () => {
    expect(() => locateGhidra({ ATLAS_TOOLS_DIR: "/nonexistent" })).toThrow(/scripts\/setup\.sh/);
    expect(() => locateGhidra({ GHIDRA_INSTALL_DIR: "/nonexistent" })).toThrow(GhidraUnavailableError);
  });

  it("finds the copy installed by setup in the tools directory", () => {
    const tools = mkdtempSync(join(tmpdir(), "atlas-tools-"));
    const installed = fakeInstall(GHIDRA_VERSION);
    try {
      renameSync(installed, join(tools, `ghidra_${GHIDRA_VERSION}_PUBLIC`));
      expect(locateGhidra({ ATLAS_TOOLS_DIR: tools })).toBe(join(tools, `ghidra_${GHIDRA_VERSION}_PUBLIC`));
    } finally {
      rmSync(tools, { recursive: true });
    }
  });

  it("accepts only the reviewed version", () => {
    const good = fakeInstall(GHIDRA_VERSION);
    const bad = fakeInstall("12.2");
    try {
      expect(locateGhidra({ GHIDRA_INSTALL_DIR: good })).toBe(good);
      expect(() => locateGhidra({ GHIDRA_INSTALL_DIR: bad })).toThrow(/12\.2/);
    } finally {
      rmSync(good, { recursive: true });
      rmSync(bad, { recursive: true });
    }
  });
});

// Real Ghidra on the stripped Lua build, scored against the symbol build. Runs where Ghidra is installed and the
// fixture built (scripts/setup.sh does both). CI runs setup and sets ATLAS_REQUIRE_FIXTURES=1, so there it must run.
describe("Ghidra on stripped Lua", () => {
  it("can run, or the run does not require it", () => {
    expect(runnable || process.env.ATLAS_REQUIRE_FIXTURES !== "1").toBe(true);
  });

  it.runIf(runnable)(
    "finds the functions of the symbol build at their addresses",
    { timeout: 10 * 60 * 1000 },
    async () => {
      const analysis = await analyseWithGhidra({ path: join(lua, "lua.stripped") }, { installDir: locateGhidra() });
      const truth = new Set(
        execFileSync("nm", ["--defined-only", join(lua, "lua.symbols")], { encoding: "utf8" })
          .split("\n")
          .map((line) => line.split(" "))
          .filter(([, type]) => type === "T" || type === "t")
          .map(([address]) => `0x${BigInt(`0x${address}`).toString(16)}`),
      );
      const found = analysis.functions.filter((f) => !f.thunk).map((f) => f.address);
      const hits = found.filter((a) => truth.has(a)).length;
      // Measured on 4 November 2026 with Ghidra 12.1.4 and GCC 13.3: 708 of 711 found, 1 extra (recall 0.996,
      // precision 0.999), and 2,872 distinct caller and callee pairs. The bounds leave room for another compiler's output, not for a regression in the adapter.
      expect(hits / truth.size).toBeGreaterThan(0.98);
      expect(hits / found.length).toBeGreaterThan(0.98);
      expect(analysis.calls.length).toBeGreaterThan(2800);
      const banner = analysis.strings.find((s) => s.value.includes("Lua 5.4"));
      expect(banner?.readers.length).toBeGreaterThan(0);
    },
  );
});
