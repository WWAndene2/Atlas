import { describe, expect, it } from "vitest";
import { binaryKind } from "../../src/tools/binary-kind.js";

const bytes = (...b: number[]): Uint8Array => new Uint8Array([...b, 0, 0, 0, 0, 0, 0, 0, 0]);

describe("binaryKind", () => {
  it("recognises executables by their first bytes", () => {
    expect(binaryKind(bytes(0x7f, 0x45, 0x4c, 0x46))).toBe("elf");
    expect(binaryKind(bytes(0x4d, 0x5a))).toBe("pe");
    expect(binaryKind(bytes(0xcf, 0xfa, 0xed, 0xfe))).toBe("macho");
    expect(binaryKind(bytes(0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2))).toBe("macho-fat");
    expect(binaryKind(new TextEncoder().encode("dex\n035\0"))).toBe("dex");
  });

  it("tells a Java class from a fat Mach-O and ignores other data", () => {
    expect(binaryKind(bytes(0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52))).toBeUndefined();
    expect(binaryKind(new TextEncoder().encode("<manifest/>"))).toBeUndefined();
  });
});
