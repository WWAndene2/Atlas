// Reads a compiled object file into what the recompile check needs: each code section's bytes and the places
// relocations will fill at link time. Two formats cover the toolchains in view: ELF (GCC and Clang for Linux,
// Android, consoles and embedded targets; read with readelf, which handles every ELF architecture) and COFF (MinGW
// and MSVC for Windows; read here, following Microsoft's PE/COFF specification).
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";

const run = promisify(execFile);

export interface ObjectSymbol {
  name: string;
  /** Name of the section the symbol is defined in. */
  section: string;
  /** Offset within that section. */
  value: number;
  /** Size in bytes, when the format records it (ELF does, COFF does not). */
  size?: number;
}

export interface ObjectFile {
  sections: ObjectSection[];
  symbols: ObjectSymbol[];
}

export interface ObjectSection {
  name: string;
  bytes: Uint8Array;
  /** Relocation holes: offset within the section and number of bytes the linker writes there. */
  relocations: { offset: number; width: number }[];
}

// ELF relocation widths by type name; unlisted types default to 4 bytes, the common case.
function elfRelocationWidth(type: string): number {
  if (/_64$|ABS64|GLOB_DAT|JUMP_SLOT/.test(type)) return 8;
  if (/_16$|ABS16/.test(type)) return 2;
  return 4;
}

async function readElf(path: string, bytes: Uint8Array): Promise<ObjectFile> {
  const { stdout: sectionList } = await run("readelf", ["-SW", path]);
  const { stdout: symbolList } = await run("readelf", ["-sW", path]);
  const { stdout: relocationList } = await run("readelf", ["-rW", path]);
  const holes = new Map<string, { offset: number; width: number }[]>();
  let current: string | undefined;
  for (const line of relocationList.split("\n")) {
    const header = /^Relocation section '\.rela?(\S+)'/.exec(line);
    if (header) {
      current = header[1];
      continue;
    }
    const m = /^([0-9a-f]+)\s+[0-9a-f]+\s+(R_\S+)/.exec(line.trim());
    if (m && current !== undefined) {
      const list = holes.get(current) ?? [];
      list.push({ offset: parseInt(m[1] ?? "0", 16), width: elfRelocationWidth(m[2] ?? "") });
      holes.set(current, list);
    }
  }
  const sections: ObjectSection[] = [];
  const sectionNames = new Map<number, string>();
  for (const m of sectionList.matchAll(/\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)/g)) {
    const [index, name, type] = [Number(m[1]), m[2] ?? "", m[3] ?? ""];
    const [offset, size] = [parseInt(m[4] ?? "0", 16), parseInt(m[5] ?? "0", 16)];
    sectionNames.set(index, name);
    if (type !== "PROGBITS") continue;
    sections.push({ name, bytes: bytes.subarray(offset, offset + size), relocations: holes.get(name) ?? [] });
  }
  const symbols: ObjectSymbol[] = [];
  const arm32 = bytes[4] === 1 && new DataView(bytes.buffer, bytes.byteOffset).getUint16(18, bytes[5] !== 2) === 40;
  for (const line of symbolList.split("\n")) {
    // Num: Value Size Type Bind Vis Ndx Name
    const f = line.trim().split(/\s+/);
    if (f.length < 8 || f[3] !== "FUNC" || !/^\d+$/.test(f[6] ?? "")) continue;
    const section = sectionNames.get(Number(f[6]));
    if (section === undefined) continue;
    // 32-bit ARM marks Thumb functions with bit 0 of their value; the code itself starts at the even address.
    const value = parseInt(f[1] ?? "0", 16);
    symbols.push({ name: f[7] ?? "", section, value: arm32 ? value & ~1 : value, size: Number(f[2]) });
  }
  return { sections, symbols };
}

// COFF relocation widths by machine and type (PE/COFF specification, "Type Indicators").
function coffRelocationWidth(machine: number, type: number): number {
  if (machine === 0x8664) return type === 0x1 ? 8 : type === 0xa ? 2 : 4; // AMD64: ADDR64, SECTION, others 32-bit
  if (machine === 0x14c) return type === 0xa ? 2 : 4; // i386: SECTION, others 32-bit
  if (machine === 0xaa64) return type === 0xe ? 8 : type === 0xd ? 2 : 4; // ARM64: ADDR64, SECTION
  return 4;
}

function readCoff(bytes: Uint8Array): ObjectFile {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const machine = view.getUint16(0, true);
  const count = view.getUint16(2, true);
  const symbolTable = view.getUint32(8, true);
  const symbolCount = view.getUint32(12, true);
  const optional = view.getUint16(16, true);
  const strings = symbolTable + symbolCount * 18; // the string table follows the symbol table
  const sections: ObjectSection[] = [];
  for (let i = 0; i < count; i++) {
    const at = 20 + optional + i * 40;
    let name = new TextDecoder("latin1").decode(bytes.subarray(at, at + 8)).replace(/\0.*$/, "");
    // A name longer than 8 bytes is "/<decimal offset>" into the string table.
    if (name.startsWith("/")) {
      const start = strings + Number(name.slice(1));
      const end = bytes.indexOf(0, start);
      name = new TextDecoder("latin1").decode(bytes.subarray(start, end < 0 ? undefined : end));
    }
    const size = view.getUint32(at + 16, true);
    const data = view.getUint32(at + 20, true);
    const relocationsAt = view.getUint32(at + 24, true);
    const relocationCount = view.getUint16(at + 32, true);
    const relocations = [];
    for (let r = 0; r < relocationCount; r++) {
      const ra = relocationsAt + r * 10;
      relocations.push({
        offset: view.getUint32(ra, true),
        width: coffRelocationWidth(machine, view.getUint16(ra + 8, true)),
      });
    }
    let content = data === 0 ? new Uint8Array(size) : bytes.subarray(data, data + size);
    // The assembler pads a COFF section to its alignment with nop (0x90) or int3 (0xcc) on x86, and the padding counts
    // in the section's size; a linked program pads differently. Measured on Lua with MinGW: every function compared
    // its padding with the next function's start. The padding is cut, never below a relocated byte.
    if (machine === 0x8664 || machine === 0x14c) {
      const lastRelocated = Math.max(0, ...relocations.map((r) => r.offset + r.width));
      let end = content.length;
      while (end > lastRelocated && (content[end - 1] === 0x90 || content[end - 1] === 0xcc)) end--;
      content = content.subarray(0, end);
    }
    sections.push({ name, bytes: content, relocations });
  }
  // Symbol table: 18-byte records; a name of more than 8 bytes is a string-table offset after four zero bytes.
  // Function symbols have type 0x20; section numbers count from 1. COFF records no size: a function ends where the
  // next symbol of its section starts (see functionExtent).
  const symbols: ObjectSymbol[] = [];
  for (let i = 0; i < symbolCount; i++) {
    const at = symbolTable + i * 18;
    const auxiliary = bytes[at + 17] ?? 0;
    const sectionNumber = view.getInt16(at + 12, true);
    const type = view.getUint16(at + 14, true);
    if (sectionNumber > 0 && type === 0x20) {
      let name: string;
      if (view.getUint32(at, true) === 0) {
        const start = strings + view.getUint32(at + 4, true);
        const end = bytes.indexOf(0, start);
        name = new TextDecoder("latin1").decode(bytes.subarray(start, end < 0 ? undefined : end));
      } else {
        name = new TextDecoder("latin1").decode(bytes.subarray(at, at + 8)).replace(/\0.*$/, "");
      }
      const section = sections[sectionNumber - 1];
      if (section !== undefined) symbols.push({ name, section: section.name, value: view.getUint32(at + 8, true) });
    }
    i += auxiliary;
  }
  return { sections, symbols };
}

export async function readObjectFile(path: string): Promise<ObjectFile> {
  const bytes = new Uint8Array(await readFile(path));
  if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) return readElf(path, bytes);
  const machine = bytes.length >= 2 ? (bytes[0] as number) | ((bytes[1] as number) << 8) : 0;
  if ([0x8664, 0x14c, 0xaa64, 0x1c4].includes(machine)) return readCoff(bytes);
  throw new Error("the compiler produced an object file that is neither ELF nor COFF");
}

/** The section holding one function compiled with -ffunction-sections: .text.<name> (ELF) or .text$<name> (COFF),
 * also with a placement kind before the name (.text.startup.main, .text.unlikely.f). */
export function functionSection({ sections }: ObjectFile, name: string): ObjectSection | undefined {
  const escaped = name.replace(/[$]/g, "\\$");
  const pattern = new RegExp(`^\\.text[.$](?:\\w+[.$])?${escaped}$`);
  return sections.find((s) => pattern.test(s.name));
}

/**
 * The bytes from the start of function `first` to the end of function `last`, both defined in one section (a unit
 * compiled without -ffunction-sections), with the relocations that fall inside, offsets made relative to the start.
 */
export function functionRun(
  object: ObjectFile,
  first: string,
  last: string,
): { bytes: Uint8Array; relocations: { offset: number; width: number }[] } | undefined {
  const start = object.symbols.find((s) => s.name === first);
  const end = object.symbols.find((s) => s.name === last);
  if (start === undefined || end === undefined || start.section !== end.section || end.value < start.value)
    return undefined;
  const section = object.sections.find((s) => s.name === start.section);
  if (section === undefined) return undefined;
  // ELF gives the size; in COFF the last function ends at the next symbol of the section, or the section's end.
  const following = object.symbols
    .filter((s) => s.section === end.section && s.value > end.value)
    .reduce((min, s) => Math.min(min, s.value), section.bytes.length);
  const stop = end.size !== undefined ? end.value + end.size : following;
  return {
    bytes: section.bytes.subarray(start.value, stop),
    relocations: section.relocations
      .filter((r) => r.offset >= start.value && r.offset < stop)
      .map((r) => ({ offset: r.offset - start.value, width: r.width })),
  };
}

/** Every function defined in an object, with its bytes and relocation holes: the reference library matching uses. */
export function objectFunctions(
  object: ObjectFile,
): { name: string; bytes: Uint8Array; relocations: { offset: number; width: number }[] }[] {
  const out = [];
  for (const symbol of object.symbols) {
    const run = functionRun(object, symbol.name, symbol.name);
    if (run !== undefined && run.bytes.length > 0) out.push({ name: symbol.name, ...run });
  }
  return out;
}
