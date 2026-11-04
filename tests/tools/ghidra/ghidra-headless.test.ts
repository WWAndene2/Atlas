import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
const ghidra = process.env.GHIDRA_INSTALL_DIR;
const runnable = ghidra !== undefined && existsSync(join(lua, "lua.stripped"));

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
    expect(() => locateGhidra({})).toThrow(/GHIDRA_INSTALL_DIR/);
    expect(() => locateGhidra({ GHIDRA_INSTALL_DIR: "/nonexistent" })).toThrow(GhidraUnavailableError);
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

// Real Ghidra on the stripped Lua build, scored against the symbol build. Runs where GHIDRA_INSTALL_DIR is set and
// the fixture is built (tests/fixtures/lua/build.sh); CI runs it once setup installs Ghidra (roadmap M1, step 5).
describe.runIf(runnable)("Ghidra on stripped Lua", () => {
  it("finds the functions of the symbol build at their addresses", { timeout: 10 * 60 * 1000 }, async () => {
    const analysis = await analyseWithGhidra(join(lua, "lua.stripped"), { installDir: locateGhidra() });
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
    expect(analysis.strings.some((s) => s.value.includes("Lua 5.4"))).toBe(true);
  });
});
