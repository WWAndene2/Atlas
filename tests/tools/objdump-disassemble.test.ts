import { describe, expect, it } from "vitest";
import { disassemble } from "../../src/tools/objdump/index.js";

describe("disassemble", () => {
  it("disassembles raw x86-64 code at its address, with each instruction's bytes", async () => {
    // endbr64; mov %rdi,%rax; ret
    const code = Uint8Array.from([0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x89, 0xf8, 0xc3]);
    expect(await disassemble(code, "x86_64", "0x401000")).toEqual([
      { address: "0x401000", bytes: "f30f1efa", text: "endbr64" },
      { address: "0x401004", bytes: "4889f8", text: "mov %rdi,%rax" },
      { address: "0x401007", bytes: "c3", text: "ret" },
    ]);
  });

  it("disassembles ARM and AArch64 with their own objdump", async () => {
    // ARM: bx lr (e12fff1e); AArch64: ret (d65f03c0)
    expect((await disassemble(Uint8Array.from([0x1e, 0xff, 0x2f, 0xe1]), "arm-v6k", "0x100000"))[0]?.text).toBe(
      "bx lr",
    );
    expect((await disassemble(Uint8Array.from([0xc0, 0x03, 0x5f, 0xd6]), "arm64", "0x0"))[0]?.text).toBe("ret");
  });
});
