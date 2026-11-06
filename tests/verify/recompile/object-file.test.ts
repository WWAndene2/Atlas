import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { functionSection, readObjectFile } from "../../../src/verify/recompile/object-file.js";
import { recompileCheck } from "../../../src/verify/recompile/recompile-check.js";

// Windows toolchains produce COFF objects. Runs where MinGW-w64 is installed (scripts/setup.sh); required in CI.
const mingw = "x86_64-w64-mingw32-gcc";
const available = spawnSync(mingw, ["--version"]).status === 0;
const source = "extern int g(int);\nint f(int x) { return g(x * 3) + 1; }\n";

function coffObject(): string {
  const dir = mkdtempSync(join(tmpdir(), "atlas-coff-"));
  writeFileSync(join(dir, "f.c"), source);
  execFileSync(mingw, ["-O2", "-ffunction-sections", "-c", join(dir, "f.c"), "-o", join(dir, "f.o")]);
  return join(dir, "f.o");
}

describe("COFF objects", () => {
  it("can be built, or the run does not require it", () => {
    expect(available || process.env.ATLAS_REQUIRE_FIXTURES !== "1").toBe(true);
  });

  it.runIf(available)("give a function's section, its relocations, and no alignment padding", async () => {
    const section = functionSection(await readObjectFile(coffObject()), "f");
    expect(section?.name).toBe(".text$f");
    expect(section?.relocations.length).toBeGreaterThan(0);
    expect(section?.bytes[section.bytes.length - 1]).not.toBe(0x90);
  });

  it.runIf(available)(
    "pass the recompile check against a linked copy with another call target and padding",
    async () => {
      const section = functionSection(await readObjectFile(coffObject()), "f");
      const linked = new Uint8Array([...(section?.bytes ?? []), 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00]);
      for (const r of section?.relocations ?? []) linked.fill(0x5a, r.offset, r.offset + r.width);
      const result = await recompileCheck({
        source,
        name: "f",
        original: linked,
        minimumSize: section?.bytes.length ?? 1,
        toolchain: { cc: mingw, flags: ["-O2"] },
      });
      expect(result.result).toBe("pass");
    },
  );
});
