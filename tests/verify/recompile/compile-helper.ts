// Test helper: compiles C and returns one function's bytes from the object, as an "original" to check against.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export function compiledBytes(source: string, name: string, flags: string[] = ["-O2"]): Uint8Array {
  const dir = mkdtempSync(join(tmpdir(), "atlas-test-cc-"));
  try {
    writeFileSync(join(dir, "f.c"), source);
    execFileSync("gcc", [...flags, "-ffunction-sections", "-c", join(dir, "f.c"), "-o", join(dir, "f.o")]);
    const sections = execFileSync("readelf", ["-SW", join(dir, "f.o")], { encoding: "utf8" });
    const m = new RegExp(`\\]\\s+\\.text\\.${name}\\s+\\S+\\s+[0-9a-f]+\\s+([0-9a-f]+)\\s+([0-9a-f]+)`).exec(sections);
    if (m === null) throw new Error(`no .text.${name}`);
    const offset = parseInt(m[1] ?? "0", 16);
    return new Uint8Array(readFileSync(join(dir, "f.o")).subarray(offset, offset + parseInt(m[2] ?? "0", 16)));
  } finally {
    rmSync(dir, { recursive: true });
  }
}
