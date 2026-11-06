// Finds the strings compilers leave in what they build: GCC and Clang write their version into ELF .comment sections
// (and MinGW into its objects' .rdata$zzz), Microsoft's toolchain leaves its own markers. Read from the whole file
// in chunks, since a game's executable can be large. Each clue is reported as found: untrusted target data.
import type { ByteSource } from "./byte-source.js";

const PATTERNS = [
  /GCC: \([^)\0\n]{0,80}\) [\w.~+-]{1,40}/g,
  /clang version [\w.~+-]{1,40}/g,
  /Microsoft \(R\)[ -~]{0,80}/g,
];

export function compilerClues(source: ByteSource): string[] {
  const found = new Set<string>();
  const chunk = 4 * 1024 * 1024;
  const overlap = 256; // a clue split across two chunks is found in the next one
  for (let at = 0; at < source.size; at += chunk - overlap) {
    const text = new TextDecoder("latin1").decode(source.read(at, chunk));
    for (const pattern of PATTERNS) for (const m of text.matchAll(pattern)) found.add(m[0]);
    if (found.size >= 16) break;
  }
  return [...found].sort();
}
