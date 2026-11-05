// Reads the function symbols of an unstripped binary: the answer key that names are scored against. ELF through
// readelf (any architecture, any byte order), PE/COFF through nm. Addresses as the file states them, matching the
// graph's (Atlas keeps each file's own addresses).
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { binaryKind } from "../binary-kind.js";
import { fileSource } from "../byte-source.js";

const run = promisify(execFile);

export interface FunctionSymbol {
  /** Lowercase hex with 0x; the Thumb bit of 32-bit ARM symbols is cleared. */
  address: string;
  name: string;
}

export async function functionSymbols(path: string): Promise<FunctionSymbol[]> {
  const source = fileSource(path);
  const kind = binaryKind(source.read(0, 64));
  source.close();
  const symbols = new Map<string, string>();
  if (kind === "elf") {
    const { stdout } = await run("readelf", ["-sW", path], { maxBuffer: 256 * 1024 * 1024 });
    for (const line of stdout.split("\n")) {
      // Num: Value Size Type Bind Vis Ndx Name
      const f = line.trim().split(/\s+/);
      if (f.length < 8 || f[3] !== "FUNC" || f[6] === "UND") continue;
      const address = `0x${(BigInt(`0x${f[1] ?? "0"}`) & ~1n).toString(16)}`;
      const name = (f[7] ?? "").replace(/@.*$/, "");
      // Several names can share an address (aliases): the first, from .symtab before .dynsym duplicates, is kept.
      if (!symbols.has(address)) symbols.set(address, name);
    }
  } else if (kind === "pe") {
    const { stdout } = await run("x86_64-w64-mingw32-nm", ["--defined-only", path], { maxBuffer: 256 * 1024 * 1024 });
    for (const line of stdout.split("\n")) {
      const [value, type, name] = line.trim().split(/\s+/);
      if (value === undefined || name === undefined || (type !== "T" && type !== "t")) continue;
      const address = `0x${BigInt(`0x${value}`).toString(16)}`;
      if (!symbols.has(address)) symbols.set(address, name);
    }
  } else {
    throw new Error(`${path}: answer keys are read from ELF or PE files`);
  }
  return [...symbols].map(([address, name]) => ({ address, name }));
}
