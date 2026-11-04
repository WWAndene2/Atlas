import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Checks the guarantee build.sh gives the answer key: every function of lua.elf sits in lua.bin at its address
// minus the base, with the same bytes. Built by tests/fixtures/lua-arm/build.sh; required in CI
// (ATLAS_REQUIRE_FIXTURES=1), skipped elsewhere when absent.
const buildDir = join(dirname(fileURLToPath(import.meta.url)), "build");
const elf = join(buildDir, "lua.elf");
const bin = join(buildDir, "lua.bin");
const built = existsSync(elf) && existsSync(bin);
const ARM_BASE = 0x100000;

describe("Lua ARM fixture", () => {
  it("is built, or the run does not require it", () => {
    expect(built || process.env.ATLAS_REQUIRE_FIXTURES !== "1").toBe(true);
  });

  it.runIf(built)("holds each function's bytes at its address minus the base", () => {
    const sections = execFileSync("readelf", ["-SW", elf], { encoding: "utf8" });
    const text = /\]\s+\.text\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)/.exec(sections);
    expect(text).not.toBeNull();
    const [address, offset, size] = (text?.slice(1, 4) ?? []).map((h) => parseInt(h, 16)) as [number, number, number];
    const fromElf = readFileSync(elf).subarray(offset, offset + size);
    const fromBin = readFileSync(bin).subarray(address - ARM_BASE, address - ARM_BASE + size);
    expect(fromBin.equals(fromElf)).toBe(true);
  });
});
