// A function's fingerprint for fuzzy matching: its instructions with addresses and constants blanked (they move
// between builds and versions), taken three at a time. Two builds of one source function share most of these
// shingles even when registers, layout or a few instructions differ; unrelated functions share few.
import { createHash } from "node:crypto";
import type { Architecture } from "../tools/engine-analysis.js";
import { disassemble } from "../tools/objdump/index.js";

/** Mnemonic and operands with numbers and symbol comments blanked. */
export function normalise(text: string): string {
  return text
    .replace(/<[^>]*>/g, "")
    .replace(/#.*$/, "")
    .replace(/[-+]?(0x[0-9a-f]+|\b\d+\b)/gi, "N")
    .replace(/\s+/g, " ")
    .trim();
}

export async function fingerprint(code: Uint8Array, architecture: Architecture, address: string): Promise<Set<string>> {
  const lines = (await disassemble(code, architecture, address)).map((i) => normalise(i.text));
  const shingles = new Set<string>();
  for (let i = 0; i + 3 <= lines.length; i++) {
    shingles.add(
      createHash("sha1")
        .update(lines.slice(i, i + 3).join("\n"))
        .digest("hex")
        .slice(0, 16),
    );
  }
  if (lines.length > 0 && lines.length < 3)
    shingles.add(createHash("sha1").update(lines.join("\n")).digest("hex").slice(0, 16));
  return shingles;
}

export function jaccard(a: Set<string>, b: Set<string>): number {
  let shared = 0;
  for (const s of a) if (b.has(s)) shared++;
  const union = a.size + b.size - shared;
  return union === 0 ? 0 : shared / union;
}
