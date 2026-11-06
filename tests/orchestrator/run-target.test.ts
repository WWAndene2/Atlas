import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { reportMarkdown, runTarget } from "../../src/orchestrator/run-target.js";
import { locateGhidra } from "../../src/tools/ghidra/index.js";

// The whole job on the Windows Lua program, from the file alone. Runs where Ghidra, MinGW and the fixture are
// installed (scripts/setup.sh); required in CI. Measured by hand on raw ARM Lua: 881 functions, 9 stubs, 198 library,
// 60 verified, 618 open, in about 3 minutes.
const exe = fileURLToPath(new URL("../fixtures/lua-platforms/build/lua.exe", import.meta.url));
const runnable = (() => {
  try {
    locateGhidra();
    return existsSync(exe);
  } catch {
    return false;
  }
})();

describe("runTarget", () => {
  it("can run, or the run does not require it", () => {
    expect(runnable || process.env.ATLAS_REQUIRE_FIXTURES !== "1").toBe(true);
  });

  it.runIf(runnable)(
    "loads, decompiles, detects, matches, verifies and reports",
    { timeout: 30 * 60 * 1000 },
    async () => {
      const store = new GraphStore(":memory:");
      const report = await runTarget(store, exe, "make Lua recompilable");
      store.close();
      const [b] = report.binaries;
      expect(b?.toolchain?.cc).toBe("x86_64-w64-mingw32-gcc");
      expect(b?.library).toBeGreaterThan(50);
      expect(b?.verified).toBeGreaterThan(50);
      expect(b?.open).toBeGreaterThan(0);
      expect(b?.problems).toEqual([]);
      const markdown = reportMarkdown(report);
      expect(markdown).toContain("Goal: make Lua recompilable");
      expect(markdown).toContain("library code (linked, not rewritten)");
    },
  );
});
