import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { readCoverage } from "../../../src/verify/replay/read-coverage.js";

describe("readCoverage", () => {
  it("reads the addresses a run reached, or undefined when nothing was written", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-read-coverage-"));
    writeFileSync(join(dir, "c.txt"), "0x1000\n0x1040\n0x1000\n");
    expect(await readCoverage(join(dir, "c.txt"))).toEqual(new Set(["0x1000", "0x1040"]));
    expect(await readCoverage(join(dir, "missing.txt"))).toBeUndefined();
  });
});
