import { describe, expect, it } from "vitest";
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
    const members = zipMembers(zip);
    expect(members.map((m) => [m.name, m.size])).toEqual([
      ["dir/a.txt", a.length],
      ["b.bin", 3],
    ]);
    expect(members[0]?.read()).toEqual(a);
    expect(members[1]?.read()).toEqual(b);
  });

  it("refuses what is not a ZIP and a member past the end", () => {
    expect(isZip(new Uint8Array(10))).toBe(false);
    expect(() => zipMembers(new Uint8Array(100))).toThrow(ZipError);
    const zip = buildZip([{ name: "x", data: new Uint8Array(50), deflate: false }]);
    new DataView(zip.buffer).setUint32(18, 0xffff, true); // local header claims more than the archive holds
    const members = zipMembers(zip);
    new DataView(zip.buffer).setUint32(zip.length - 22 - 46 + 20, 0xfffff, true);
    expect(() => zipMembers(zip)[0]?.read()).toThrow(ZipError);
    expect(members).toHaveLength(1);
  });
});
