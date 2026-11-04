import { readFileSync, existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { headerArchitecture, isSharedLibrary } from "../../src/tools/binary-header.js";
import { bytesSource } from "../../src/tools/byte-source.js";
import { compilerClues } from "../../src/tools/compiler-clues.js";

const fixtures = new URL("../fixtures/", import.meta.url);
const file = (path: string): Uint8Array | undefined => {
  const url = new URL(path, fixtures);
  return existsSync(url) ? new Uint8Array(readFileSync(url)) : undefined;
};
const elf = file("lua/build/lua.stripped");
const exe = file("lua-platforms/build/lua.exe");
const so = file("lua-platforms/build/liblua.so");

describe("headerArchitecture", () => {
  it("knows nothing about bytes without a header", () => {
    expect(headerArchitecture(new Uint8Array(64))).toBeUndefined();
    expect(isSharedLibrary(new Uint8Array(64))).toBe(false);
  });

  it.runIf(elf !== undefined && exe !== undefined && so !== undefined)("reads ELF and PE headers", () => {
    expect(headerArchitecture(elf as Uint8Array)).toBe("x86_64");
    expect(headerArchitecture(exe as Uint8Array)).toBe("x86_64");
    expect(headerArchitecture(so as Uint8Array)).toBe("arm64");
    // A position-independent executable is not a library; a .so is.
    expect(isSharedLibrary(elf as Uint8Array)).toBe(false);
    expect(isSharedLibrary(so as Uint8Array)).toBe(true);
  });
});

describe("compilerClues", () => {
  it("finds compiler version strings, including one split across read chunks", () => {
    const bytes = new Uint8Array(4 * 1024 * 1024 + 100);
    const clue = new TextEncoder().encode("GCC: (GNU) 13-win32");
    bytes.set(clue, 4 * 1024 * 1024 - 8);
    bytes.set(new TextEncoder().encode("clang version 18.1.3"), 50);
    expect(compilerClues(bytesSource(bytes))).toEqual(["GCC: (GNU) 13-win32", "clang version 18.1.3"]);
  });
});
