import { describe, expect, it } from "vitest";
import { GhidraExportError, parseGhidraExport } from "../../../src/tools/ghidra/index.js";

const sha256 = "c".repeat(64);

function document(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    format: "atlas-ghidra-export",
    format_version: 1,
    ghidra_version: "12.1.4",
    sha256,
    language: "x86:LE:64:default",
    image_base: "0x0",
    functions: [
      { address: "0x1000", size: 16, label: "FUN_00001000", thunk: false, external: false },
      { address: "0x1010", size: 6, label: "puts", thunk: true, external: false },
      { address: "0x2", size: 0, label: "puts", thunk: false, external: true },
    ],
    calls: [
      { from: "0x1000", to: "0x1010", site: "0x1004" },
      { from: "0x1000", to: "0x1010", site: "0x1008" },
      { from: "0x1010", to: "0x2", site: "0x1010" },
    ],
    strings: [{ address: "0x3000", value: "hello\n", readers: ["0x1000", "0x2"] }],
    ...overrides,
  });
}

describe("parseGhidraExport", () => {
  it("keeps the file's functions and one call per caller and callee pair", () => {
    const analysis = parseGhidraExport(document());
    expect(analysis.tool).toEqual({ name: "ghidra", version: "12.1.4" });
    expect(analysis.sha256).toBe(sha256);
    expect(analysis.functions.map((f) => f.address)).toEqual(["0x1000", "0x1010"]);
    expect(analysis.functions[1]?.thunk).toBe(true);
    expect(analysis.calls).toEqual([{ from: "0x1000", to: "0x1010" }]);
    expect(analysis.strings).toEqual([{ address: "0x3000", value: "hello\n", readers: ["0x1000"] }]);
    expect(analysis.limitations.length).toBeGreaterThan(0);
  });

  it("refuses a document that is not the export format", () => {
    expect(() => parseGhidraExport("not json")).toThrow(GhidraExportError);
    expect(() => parseGhidraExport(document({ format_version: 2 }))).toThrow(GhidraExportError);
  });

  it("refuses malformed fields instead of loading them", () => {
    expect(() => parseGhidraExport(document({ sha256: "xyz" }))).toThrow(GhidraExportError);
    expect(() =>
      parseGhidraExport(
        document({ functions: [{ address: "4096", size: 1, label: "f", thunk: false, external: false }] }),
      ),
    ).toThrow(GhidraExportError);
    expect(() => parseGhidraExport(document({ strings: [{ address: "0x1", value: 3, readers: [] }] }))).toThrow(
      GhidraExportError,
    );
  });
});
