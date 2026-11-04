import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../../src/graph/index.js";
import { decompileFunctions } from "../../../src/orchestrator/decompile-functions.js";
import { loadTarget } from "../../../src/orchestrator/load-target.js";
import { parseGhidraDecompile } from "../../../src/tools/ghidra/index.js";
import { locateGhidra } from "../../../src/tools/ghidra/index.js";
import { verifyRewrite } from "../../../src/verify/recompile/verify-rewrite.js";
import type { Hypothesis } from "../../../src/graph/index.js";

const stripped = fileURLToPath(new URL("../../fixtures/lua/build/lua.stripped", import.meta.url));
const runnable = (() => {
  try {
    locateGhidra();
    return existsSync(stripped);
  } catch {
    return false;
  }
})();

describe("parseGhidraDecompile", () => {
  it("reads C and failures, and refuses another format", () => {
    const text = JSON.stringify({
      format: "atlas-ghidra-decompile",
      format_version: 1,
      functions: [
        { address: "0x10", label: "f", c: "int f(void) { return 1; }" },
        { address: "0x20", label: "g", error: "timeout" },
      ],
    });
    expect(parseGhidraDecompile(text)).toEqual([
      { address: "0x10", label: "f", c: "int f(void) { return 1; }" },
      { address: "0x20", label: "g", error: "timeout" },
    ]);
    expect(() => parseGhidraDecompile("{}")).toThrow();
  });
});

describe("Ghidra's C for Lua, recompiled", () => {
  it("can run, or the run does not require it", () => {
    expect(runnable || process.env.ATLAS_REQUIRE_FIXTURES !== "1").toBe(true);
  });

  // The baseline the rewrite loop starts from. Measured on 4 November 2026 (Ghidra 12.1.4, GCC 13.3 -O2): of 709
  // functions, 19 recompile byte for byte as Ghidra wrote them, 439 compile but differ, 251 do not compile.
  it.runIf(runnable)(
    "decompiles every function and verifies those that recompile as written",
    { timeout: 20 * 60 * 1000 },
    async () => {
      const store = new GraphStore(":memory:");
      await loadTarget(store, { path: stripped });
      const { proposed } = await decompileFunctions(store, { path: stripped });
      expect(proposed.length).toBeGreaterThan(690);
      let verified = 0;
      for (const h of proposed as Hypothesis[]) {
        const { check } = await verifyRewrite(store, h.id, { cc: "gcc", flags: ["-std=gnu99", "-O2"] });
        if (check.result === "pass") verified++;
      }
      store.close();
      expect(verified).toBeGreaterThanOrEqual(15);
    },
  );
});
