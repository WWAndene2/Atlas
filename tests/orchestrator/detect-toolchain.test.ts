import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { binaryFacts } from "../../src/orchestrator/binary-facts.js";
import { decompileFunctions } from "../../src/orchestrator/decompile-functions.js";
import { binaryToolchain, detectToolchain } from "../../src/orchestrator/detect-toolchain.js";
import { loadTarget } from "../../src/orchestrator/load-target.js";
import { locateGhidra } from "../../src/tools/ghidra/index.js";

// Detection with nothing given but the file: the Windows Lua fixture was built with MinGW-w64 GCC at -O2.
// Runs where Ghidra, MinGW and the fixture are installed (scripts/setup.sh); required in CI.
const exe = fileURLToPath(new URL("../fixtures/lua-platforms/build/lua.exe", import.meta.url));
const runnable = (() => {
  try {
    locateGhidra();
    return existsSync(exe);
  } catch {
    return false;
  }
})();

describe("detectToolchain", () => {
  it("can run, or the run does not require it", () => {
    expect(runnable || process.env.ATLAS_REQUIRE_FIXTURES !== "1").toBe(true);
  });

  // Measured on 5 November 2026: x86_64-w64-mingw32-gcc -O2, 18 of 275 functions reproduced, tied with -O3; the
  // other platforms, by hand: Linux gcc -O2, Android aarch64 gcc -fPIC -O2, raw ARMv6K -marm -mfloat-abi=hard -O2.
  it.runIf(runnable)(
    "finds the compiler and flags a Windows program was built with",
    { timeout: 20 * 60 * 1000 },
    async () => {
      const store = new GraphStore(":memory:");
      const [outcome] = await loadTarget(store, { path: exe });
      const binary = outcome?.loaded?.binary ?? "";
      expect(store.getNode(binary)?.architecture).toBe("x86_64");
      await decompileFunctions(store, { path: exe });
      const facts = binaryFacts({ path: exe });
      expect(facts).toMatchObject({ architecture: "x86_64", format: "pe", sharedLibrary: false });
      expect(facts.clues.some((c) => c.startsWith("GCC:"))).toBe(true);
      const { value } = await detectToolchain(store, binary, facts, 150);
      expect(value).toMatchObject({ cc: "x86_64-w64-mingw32-gcc", flags: ["-O2"] });
      expect(binaryToolchain(store, binary)?.cc).toBe("x86_64-w64-mingw32-gcc");
      store.close();
    },
  );
});
