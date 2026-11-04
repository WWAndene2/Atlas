import { describe, expect, it } from "vitest";
import { CtrFormatError, ctrKind, readCtrCode } from "../../../src/tools/ctr/index.js";
import { buildNcch, buildNcsd, type ContainerOptions } from "./ctr-builder.js";

// Three segments as a 3DS application has them: text at 0x100000, then read-only data and data on the next pages.
const text = new Uint8Array(0x1800).map((_, i) => (i * 3) & 0xff);
const rodata = new Uint8Array(0x900).fill(0x52);
const data = new Uint8Array(0x300).fill(0x44);
const code = new Uint8Array(0x2000 + 0x1000 + 0x300);
code.set(text, 0);
code.set(rodata, 0x2000);
code.set(data, 0x3000);
const options: ContainerOptions = {
  code,
  text: { address: 0x100000, pages: 2, size: text.length },
  rodata: { address: 0x102000, pages: 1, size: rodata.length },
  data: { address: 0x103000, pages: 1, size: data.length },
  compress: true,
  title: "LUATEST",
};

describe("readCtrCode", () => {
  it("reads the code of a card image, decompressed and laid out by segment", () => {
    const image = buildNcsd(buildNcch(options));
    expect(ctrKind(image)).toBe("ncsd");
    const result = readCtrCode(image);
    expect(result).toMatchObject({
      container: "ncsd",
      title: "LUATEST",
      programId: "0004000000123400",
      base: "0x100000",
      text: { address: "0x100000", offset: 0, size: 0x1800 },
      rodata: { address: "0x102000", offset: 0x2000, size: 0x900 },
      data: { address: "0x103000", offset: 0x3000, size: 0x300 },
    });
    expect(result.image).toEqual(code);
  });

  it("reads a lone NCCH with uncompressed code", () => {
    const result = readCtrCode(buildNcch({ ...options, compress: false }));
    expect(result.container).toBe("ncch");
    expect(result.image).toEqual(code);
  });

  it("refuses encrypted content and says why", () => {
    expect(() => readCtrCode(buildNcsd(buildNcch({ ...options, encrypted: true })))).toThrow(
      /decrypted on your own console/,
    );
  });

  it("refuses what is not a 3DS container", () => {
    expect(ctrKind(new Uint8Array(0x200))).toBeUndefined();
    expect(() => readCtrCode(new Uint8Array(0x200))).toThrow(CtrFormatError);
  });

  it("refuses a truncated container instead of reading past its end", () => {
    const image = buildNcsd(buildNcch(options));
    expect(() => readCtrCode(image.subarray(0, 0x4000 + 0xb00))).toThrow(CtrFormatError);
  });
});
