import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../../src/graph/index.js";
import { loadTarget } from "../../../src/orchestrator/load-target.js";
import { resolveTarget } from "../../../src/orchestrator/resolve-target.js";
import { locateGhidra } from "../../../src/tools/ghidra/index.js";

// PC and mobile, end to end from the file the operator has: a stripped Windows program and an Android package
// holding a stripped AArch64 library. Scored against the unstripped builds. Runs where Ghidra and the fixtures are installed (scripts/setup.sh); required in CI.
const dir = fileURLToPath(new URL("../../fixtures/lua-platforms/build/", import.meta.url));
const runnable = (() => {
  try {
    locateGhidra();
    return existsSync(join(dir, "lua.apk"));
  } catch {
    return false;
  }
})();

function symbols(tool: string, file: string): Set<string> {
  return new Set(
    execFileSync(tool, ["--defined-only", file], { encoding: "utf8" })
      .split("\n")
      .map((line) => line.trim().split(/\s+/))
      .filter((f) => f.length === 3 && (f[1] === "T" || f[1] === "t"))
      .map((f) => `0x${BigInt(`0x${f[0]}`).toString(16)}`),
  );
}

async function score(file: string, truth: Set<string>): Promise<{ recall: number; precision: number }> {
  const store = new GraphStore(":memory:");
  const target = await resolveTarget(join(dir, file));
  try {
    for (const b of target.binaries) await loadTarget(store, b.input, undefined, b.label);
  } finally {
    await target.dispose();
  }
  const functions = store.nodesOfKind("function");
  store.close();
  // Recall over every function found: some toolchains give import stubs symbols of their own (MinGW does), and
  // finding them is right. Precision over the others: a stub is marked thunk, so an unmatched one misleads no one.
  const all = functions.map((n) => n.address ?? "");
  const real = functions.filter((n) => n.thunk !== true).map((n) => n.address ?? "");
  return {
    recall: all.filter((a) => truth.has(a)).length / truth.size,
    precision: real.filter((a) => truth.has(a)).length / real.length,
  };
}

describe("Ghidra on PC and mobile targets", () => {
  it("can run, or the run does not require it", () => {
    expect(runnable || process.env.ATLAS_REQUIRE_FIXTURES !== "1").toBe(true);
  });

  // Measured on 4 November 2026, Ghidra 12.1.4 with the export script's padding and import filters: Windows recall
  // 0.942, Android recall 1.000 and precision 0.999 (0.626 before the filters). Bounds guard against regression.
  it.runIf(runnable)("finds a Windows program's functions", { timeout: 10 * 60 * 1000 }, async () => {
    const { recall, precision } = await score("lua.exe", symbols("x86_64-w64-mingw32-nm", join(dir, "lua.exe.debug")));
    expect(recall).toBeGreaterThan(0.92);
    expect(precision).toBeGreaterThan(0.98);
  });

  it.runIf(runnable)(
    "finds the functions of an Android package's native library",
    { timeout: 10 * 60 * 1000 },
    async () => {
      const { recall, precision } = await score(
        "lua.apk",
        symbols("aarch64-linux-gnu-nm", join(dir, "liblua.so.debug")),
      );
      expect(recall).toBeGreaterThan(0.98);
      expect(precision).toBeGreaterThan(0.9);
    },
  );
});
