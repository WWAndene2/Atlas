import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { KsyError, locateKaitai, parseWithKsy } from "../../../src/tools/kaitai/index.js";

function kaitai() {
  try {
    return locateKaitai();
  } catch {
    return undefined;
  }
}
const tools = kaitai();

const TINY = `meta:
  id: tiny_box
  endian: le
seq:
  - id: magic
    contents: "TINY"
  - id: num_items
    type: u2
  - id: items
    type: u4
    repeat: expr
    repeat-expr: num_items
`;

describe.runIf(tools !== undefined)("parseWithKsy", () => {
  it("reads the files that fit the format and names the ones that do not", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-ksy-"));
    const file = (name: string, hex: string) => {
      writeFileSync(join(dir, name), Buffer.from(hex, "hex"));
      return join(dir, name);
    };
    const whole = file("a", "54494e59020001000000020000 00".replace(/ /g, ""));
    const trailing = file("b", "54494e5900000102");
    const short = file("c", "54494e59050001");
    const wrong = file("d", "4e4f5045");
    const { id, files } = await parseWithKsy(tools as NonNullable<typeof tools>, TINY, [whole, trailing, short, wrong]);
    expect(id).toBe("tiny_box");
    expect(files.map((f) => f.ok)).toEqual([true, true, false, false]);
    expect(files[1]).toMatchObject({ consumed: 6, size: 8 });
    expect(files[3]?.error).toContain("ValidationNotEqualError");
  }, 120_000);
  it("reports a .ksy that does not compile", async () => {
    await expect(
      parseWithKsy(tools as NonNullable<typeof tools>, "meta:\n  id: bad\nseq:\n  - id: x\n    type: nonsense\n", []),
    ).rejects.toThrow(KsyError);
  }, 120_000);
});
