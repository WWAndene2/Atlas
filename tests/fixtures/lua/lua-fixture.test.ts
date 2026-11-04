import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Checks the guarantees build.sh gives the answer key. The fixture is built by `tests/fixtures/lua/build.sh`;
// CI builds it first and sets ATLAS_REQUIRE_FIXTURES=1, so there a missing fixture fails instead of skipping.
const buildDir = join(dirname(fileURLToPath(import.meta.url)), "build");
const symbols = join(buildDir, "lua.symbols");
const stripped = join(buildDir, "lua.stripped");
const built = existsSync(symbols) && existsSync(stripped);
const required = process.env.ATLAS_REQUIRE_FIXTURES === "1";

interface Section {
  name: string;
  address: number;
  offset: number;
  size: number;
}

function sections(file: string): Map<string, Section> {
  const out = execFileSync("readelf", ["-SW", file], { encoding: "utf8" });
  const result = new Map<string, Section>();
  for (const match of out.matchAll(/\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)/g)) {
    // The pattern has exactly four groups, all mandatory.
    const [name, address, offset, size] = match.slice(1, 5) as [string, string, string, string];
    result.set(name, {
      name,
      address: parseInt(address, 16),
      offset: parseInt(offset, 16),
      size: parseInt(size, 16),
    });
  }
  return result;
}

function sectionBytes(file: string, section: Section): Buffer {
  return readFileSync(file).subarray(section.offset, section.offset + section.size);
}

describe("Lua fixture", () => {
  it("is built, or the run does not require it", () => {
    expect(built || !required).toBe(true);
  });

  it.runIf(built)("keeps symbols and debug information in the answer key only", () => {
    const keyed = sections(symbols);
    const bare = sections(stripped);
    expect(keyed.has(".symtab")).toBe(true);
    expect(keyed.has(".debug_info")).toBe(true);
    expect(bare.has(".symtab")).toBe(false);
    expect([...bare.keys()].some((name) => name.startsWith(".debug"))).toBe(false);
  });

  it.runIf(built)("has the same code at the same addresses in both files", () => {
    const keyedText = sections(symbols).get(".text");
    const bareText = sections(stripped).get(".text");
    expect(keyedText).toBeDefined();
    expect(bareText?.address).toBe(keyedText?.address);
    expect(sectionBytes(stripped, bareText as Section).equals(sectionBytes(symbols, keyedText as Section))).toBe(true);
  });

  it.runIf(built)("runs Lua code", () => {
    const out = execFileSync(stripped, ["-e", "print(6 * 7)"], { encoding: "utf8" });
    expect(out.trim()).toBe("42");
  });
});
