import { describe, expect, it } from "vitest";
import { bytesSource } from "../../../src/tools/byte-source.js";
import { ZipError, isZip, zipMembers } from "../../../src/tools/zip/index.js";
import { buildZip } from "./zip-builder.js";

describe("zipMembers", () => {
  it("reads stored and deflated members", () => {
    const a = new TextEncoder().encode("hello ".repeat(100));
    const b = new Uint8Array([1, 2, 3]);
    const zip = buildZip([
      { name: "dir/a.txt", data: a, deflate: true },
      { name: "b.bin", data: b, deflate: false },
    ]);
    expect(isZip(zip)).toBe(true);
    const members = zipMembers(bytesSource(zip));
    expect(members.map((m) => [m.name, m.size])).toEqual([
      ["dir/a.txt", a.length],
      ["b.bin", 3],
    ]);
    expect(members[0]?.read()).toEqual(a);
    expect(members[1]?.read()).toEqual(b);
  });

  it("refuses what is not a ZIP and a member past the end", () => {
    expect(isZip(new Uint8Array(10))).toBe(false);
    expect(() => zipMembers(bytesSource(new Uint8Array(100)))).toThrow(ZipError);
    const zip = buildZip([{ name: "x", data: new Uint8Array(50), deflate: false }]);
    new DataView(zip.buffer).setUint32(18, 0xffff, true); // local header claims more than the archive holds
    const members = zipMembers(bytesSource(zip));
    new DataView(zip.buffer).setUint32(zip.length - 22 - 46 + 20, 0xfffff, true);
    expect(() => zipMembers(bytesSource(zip))[0]?.read()).toThrow(ZipError);
    expect(members).toHaveLength(1);
  });

  it("peeks at a member's first bytes without reading it all", () => {
    const big = new Uint8Array(4 * 1024 * 1024).map((_, i) => i & 0xff);
    const [member] = zipMembers(bytesSource(buildZip([{ name: "big.bin", data: big, deflate: true }])));
    expect(member?.peek(8)).toEqual(big.subarray(0, 8));
  });

  it("reports a corrupt member as a ZIP error", () => {
    const zip = buildZip([{ name: "bad.bin", data: new Uint8Array(1000).fill(7), deflate: true }]);
    zip.fill(0xff, 30 + "bad.bin".length, 30 + "bad.bin".length + 4); // the member's deflate stream follows its header
    const [member] = zipMembers(bytesSource(zip));
    expect(() => member?.read()).toThrow(ZipError);
    expect(() => member?.peek(8)).toThrow(ZipError);
  });
});
