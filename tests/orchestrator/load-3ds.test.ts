import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { loadTarget } from "../../src/orchestrator/load-target.js";
import { resolveTarget, type ResolvedBinary } from "../../src/orchestrator/resolve-target.js";
import { locateGhidra } from "../../src/tools/ghidra/index.js";
import { buildNcch, buildNcsd } from "../tools/ctr/ctr-builder.js";

// End to end on a 3DS-shaped title: the ARM Lua image packed as a decrypted card image with compressed code, loaded
// from the .3ds file alone. Runs where Ghidra and the ARM fixture are installed (scripts/setup.sh); required in CI.
const bin = fileURLToPath(new URL("../fixtures/lua-arm/build/lua.bin", import.meta.url));
const runnable = (() => {
  try {
    locateGhidra();
    return existsSync(bin);
  } catch {
    return false;
  }
})();

describe("loading a 3DS title", () => {
  it("can run, or the run does not require it", () => {
    expect(runnable || process.env.ATLAS_REQUIRE_FIXTURES !== "1").toBe(true);
  });

  it.runIf(runnable)("finds the functions of its code from the .3ds file", { timeout: 10 * 60 * 1000 }, async () => {
    const image = new Uint8Array(readFileSync(bin));
    const pages = Math.ceil(image.length / 0x1000);
    const code = new Uint8Array(pages * 0x1000);
    code.set(image);
    const path = join(mkdtempSync(join(tmpdir(), "atlas-3ds-")), "lua.3ds");
    writeFileSync(
      path,
      buildNcsd(
        buildNcch({
          code,
          text: { address: 0x100000, pages, size: image.length },
          rodata: { address: 0x100000 + pages * 0x1000, pages: 0, size: 0 },
          data: { address: 0x100000 + pages * 0x1000, pages: 0, size: 0 },
          compress: true,
        }),
      ),
    );
    const store = new GraphStore(":memory:");
    const target = await resolveTarget(path);
    try {
      const [binary] = target.binaries;
      const [outcome] = await loadTarget(
        store,
        (binary as ResolvedBinary).input,
        undefined,
        (binary as ResolvedBinary).label,
      );
      // Same image as the raw ARM test (whose bounds are measured): the container must not change what is found.
      expect(outcome?.loaded?.functions).toBeGreaterThan(850);
      expect(store.nodesOfKind("binary")[0]?.label).toBe("lua.3ds:code.bin");
    } finally {
      await target.dispose();
      store.close();
    }
  });
});
