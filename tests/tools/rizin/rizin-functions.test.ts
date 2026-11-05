import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { locateRizin, rizinFunctions } from "../../../src/tools/rizin/index.js";

function rizin(): string | undefined {
  try {
    return locateRizin();
  } catch {
    return undefined;
  }
}
const found = rizin();
const lua = "tests/fixtures/lua/build/lua.stripped";

describe.runIf(found !== undefined)("rizinFunctions", () => {
  it.runIf(existsSync(lua))(
    "lists a stripped ELF's functions at the file's own addresses",
    async () => {
      const functions = await rizinFunctions(found as string, { path: lua });
      expect(functions.length).toBeGreaterThan(500);
      expect(functions.every((f) => /^0x[0-9a-f]+$/.test(f.address) && BigInt(f.address) < 0x100000n)).toBe(true);
    },
    120_000,
  );
  it("reads a raw big-endian MIPS image from its load address", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "atlas-rz-")), "code.bin");
    // addiu sp,sp,-32; jr ra; addiu sp,sp,32
    writeFileSync(path, Buffer.from("27bdffe003e0000827bd0020", "hex"));
    const functions = await rizinFunctions(found as string, {
      path,
      raw: { architecture: "mips", base: "0x400000" },
    });
    expect(functions).toEqual([{ address: "0x400000", size: 12, label: "fcn.00400000" }]);
  });
});
