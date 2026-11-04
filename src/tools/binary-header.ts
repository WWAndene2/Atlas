// Reads what a binary's header says about the CPU it runs on, mapped to Atlas's architecture names. Raw images have
// no header: their architecture comes from the operator (--arch).
import type { Architecture } from "./engine-analysis.js";

export function headerArchitecture(bytes: Uint8Array): Architecture | undefined {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (at: number): number => (at + 2 <= bytes.length ? view.getUint16(at, true) : -1);
  const u32 = (at: number): number => (at + 4 <= bytes.length ? view.getUint32(at, true) : -1);
  if (u32(0) === 0x464c457f) {
    // ELF e_machine. 32-bit ARM's exact revision is not in e_machine; v7 is the common case on phones and PCs.
    const machine = u16(18);
    if (machine === 62) return "x86_64";
    if (machine === 3) return "x86";
    if (machine === 183) return "arm64";
    if (machine === 40) return "arm-v7";
    return undefined;
  }
  if (u16(0) === 0x5a4d) {
    // PE: the COFF header's machine field, after the "PE\0\0" signature found at offset 0x3c.
    const pe = u32(0x3c);
    if (pe < 0 || u32(pe) !== 0x4550) return undefined;
    const machine = u16(pe + 4);
    if (machine === 0x8664) return "x86_64";
    if (machine === 0x14c) return "x86";
    if (machine === 0xaa64) return "arm64";
    if (machine === 0x1c4) return "arm-v7";
    return undefined;
  }
  const magic = u32(0);
  if (magic === 0xfeedfacf || magic === 0xfeedface) {
    // Mach-O cputype: x86 with or without the 64-bit flag, ARM likewise.
    const cpu = u32(4);
    if (cpu === 0x01000007) return "x86_64";
    if (cpu === 7) return "x86";
    if (cpu === 0x0100000c) return "arm64";
    if (cpu === 12) return "arm-v7";
  }
  return undefined;
}

/** An ELF shared library (a .so): compiled as position-independent code (-fPIC). */
export function isSharedLibrary(bytes: Uint8Array): boolean {
  if (bytes.length < 64 || bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46)
    return false;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint16(16, true) !== 3) return false; // ET_DYN: a library, or a position-independent executable
  // A PIE has a program interpreter (PT_INTERP, type 3); a library has none.
  const is64 = bytes[4] === 2;
  const phoff = is64 ? Number(view.getBigUint64(32, true)) : view.getUint32(28, true);
  const phentsize = view.getUint16(is64 ? 54 : 42, true);
  const phnum = view.getUint16(is64 ? 56 : 44, true);
  for (let i = 0; i < phnum; i++) {
    const at = phoff + i * phentsize;
    if (at + 4 > bytes.length) return false;
    if (view.getUint32(at, true) === 3) return false;
  }
  return true;
}
