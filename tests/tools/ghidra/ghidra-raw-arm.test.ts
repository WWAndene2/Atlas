import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { analyseWithGhidra, locateGhidra } from "../../../src/tools/ghidra/index.js";

// Real Ghidra on a raw ARM image, the shape of a 3DS code.bin: no header, no symbol, CPU and base given by Atlas.
// Scored against the symbol build. Runs where Ghidra and the fixture are installed (scripts/setup.sh); required in CI.
const dir = fileURLToPath(new URL("../../fixtures/lua-arm/build/", import.meta.url));
const runnable = (() => {
  try {
    locateGhidra();
    return existsSync(join(dir, "lua.bin"));
  } catch {
    return false;
  }
})();

describe("Ghidra on a raw ARM image", () => {
  it("can run, or the run does not require it", () => {
    expect(runnable || process.env.ATLAS_REQUIRE_FIXTURES !== "1").toBe(true);
  });

  it.runIf(runnable)("finds functions at the symbol build's addresses", { timeout: 10 * 60 * 1000 }, async () => {
    const analysis = await analyseWithGhidra(
      { path: join(dir, "lua.bin"), raw: { architecture: "arm-v6k", base: "0x100000" } },
      { installDir: locateGhidra() },
    );
    const truth = new Set(
      execFileSync("readelf", ["-sW", join(dir, "lua.elf")], { encoding: "utf8" })
        .split("\n")
        .map((line) => line.trim().split(/\s+/))
        .filter((f) => f[3] === "FUNC" && f[6] !== "UND")
        .map((f) => `0x${(parseInt(f[1] ?? "0", 16) & ~1).toString(16)}`),
    );
    const found = analysis.functions.map((f) => f.address);
    const hits = found.filter((a) => truth.has(a)).length;
    // Measured on 4 November 2026 (Ghidra 12.1.4, arm-none-eabi GCC 13.2): recall 0.82, precision 0.999. Most misses
    // are library code nothing calls (unwinder, soft-float helpers) and functions reached only through pointers in
    // data; a pass seeding those naively lowered precision to 0.87 and was not kept. Bounds guard against regression.
    expect(hits / truth.size).toBeGreaterThan(0.78);
    expect(hits / found.length).toBeGreaterThan(0.98);
    expect(analysis.strings.some((s) => s.value.includes("Lua 5.4"))).toBe(true);
  });
});
