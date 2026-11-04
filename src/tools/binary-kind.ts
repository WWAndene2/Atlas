// Recognises executable formats by their first bytes, so that Atlas picks the binaries out of a container and knows
// which ones the engines read from their own header. Content decides, never the file name (target data is untrusted).

export type BinaryKind = "elf" | "pe" | "macho" | "macho-fat" | "dex";

export function binaryKind(bytes: Uint8Array): BinaryKind | undefined {
  if (bytes.length < 8) return undefined;
  const b = (i: number): number => bytes[i] as number;
  if (b(0) === 0x7f && b(1) === 0x45 && b(2) === 0x4c && b(3) === 0x46) return "elf";
  if (b(0) === 0x4d && b(1) === 0x5a) return "pe";
  const le = (b(0) | (b(1) << 8) | (b(2) << 16) | (b(3) << 24)) >>> 0;
  if (le === 0xfeedface || le === 0xfeedfacf) return "macho";
  // 0xcafebabe opens both fat Mach-O files and Java classes; a fat file has a small architecture count next.
  const be = ((b(0) << 24) | (b(1) << 16) | (b(2) << 8) | b(3)) >>> 0;
  const next = ((b(4) << 24) | (b(5) << 16) | (b(6) << 8) | b(7)) >>> 0;
  if (be === 0xcafebabe && next > 0 && next < 32) return "macho-fat";
  if (b(0) === 0x64 && b(1) === 0x65 && b(2) === 0x78 && b(3) === 0x0a) return "dex";
  return undefined;
}
