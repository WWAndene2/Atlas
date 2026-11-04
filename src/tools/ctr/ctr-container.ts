// Reads a Nintendo 3DS title's executable code from its container: NCSD (.3ds, .cci: a card image holding NCCH
// partitions) or NCCH (.cxi, .app: one partition). From the NCCH it reads the extended header (where the code's
// segments are loaded) and the ExeFS (the .code file, BLZ-compressed when the header says so), and returns the code
// laid out as it is in memory. Layouts follow the 3DS community documentation (3dbrew: NCSD, NCCH, ExeFS, ExHeader).
// Only the headers and the code are read, by offset, so card images of several gigabytes cost no more than small ones.
//
// Only decrypted content is read. An NCCH without the NoCrypto flag is refused: decrypting it would mean bypassing
// the console's copy protection, which Atlas does not do. Dumps decrypted by the owner's
// own console are what Atlas takes.
import type { ByteSource } from "../byte-source.js";
import { blzDecompress } from "./ctr-blz.js";

export class CtrFormatError extends Error {
  constructor(message: string) {
    super(`3DS container: ${message}`);
    this.name = "CtrFormatError";
  }
}

export interface CodeSegment {
  /** Load address, lowercase hex with 0x. */
  address: string;
  /** Bytes of the segment in the code image. */
  size: number;
  /** Where the segment starts in the code image. */
  offset: number;
}

export interface CtrCode {
  /** Container kind the code came from. */
  container: "ncsd" | "ncch";
  /** Title name from the extended header (untrusted target data). */
  title: string;
  /** Program ID, 16 hex digits. */
  programId: string;
  /** The code as loaded: text, then read-only data, then data, each at its page-aligned place. */
  image: Uint8Array;
  /** Load address of the image's first byte (the text segment): the base for a raw load. */
  base: string;
  text: CodeSegment;
  rodata: CodeSegment;
  data: CodeSegment;
}

const PAGE = 0x1000;
const NO_CRYPTO = 0x04;

function u32(bytes: Uint8Array, at: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(at, true);
}

function magic(bytes: Uint8Array, at: number): string {
  return String.fromCharCode(...bytes.subarray(at, at + 4));
}

/** Exactly `size` bytes at `offset`, or a format error naming what lies past the end. */
function exact(source: ByteSource, offset: number, size: number, what: string): Uint8Array {
  if (offset < 0 || offset + size > source.size) throw new CtrFormatError(`${what} lies past the end of the file`);
  return source.read(offset, size);
}

/** Recognises a 3DS container by its magic, without reading further. */
export function ctrKind(bytes: Uint8Array): "ncsd" | "ncch" | undefined {
  if (bytes.length >= 0x104 && magic(bytes, 0x100) === "NCSD") return "ncsd";
  if (bytes.length >= 0x104 && magic(bytes, 0x100) === "NCCH") return "ncch";
  return undefined;
}

function segment(exheader: Uint8Array, at: number, offset: number, name: string): CodeSegment & { pages: number } {
  const pages = u32(exheader, at + 4);
  const size = u32(exheader, at + 8);
  if (size > pages * PAGE) throw new CtrFormatError(`${name} segment: ${size} bytes do not fit in ${pages} pages`);
  return { address: `0x${u32(exheader, at).toString(16)}`, pages, size, offset };
}

function readNcch(source: ByteSource, at: number, container: CtrCode["container"]): CtrCode {
  const header = exact(source, at, 0x200, "NCCH header");
  if (magic(header, 0x100) !== "NCCH") throw new CtrFormatError("no NCCH partition where expected");
  const flags = header.subarray(0x188, 0x190);
  if (((flags[7] as number) & NO_CRYPTO) === 0) {
    throw new CtrFormatError(
      "the NCCH is encrypted. Dump the title decrypted on your own console (for example GodMode9's decrypt option on " +
        "your cartridge or installed title), then load that file; Atlas does not remove console encryption itself",
    );
  }
  const unit = 0x200 << (flags[6] as number);
  const programId = new DataView(header.buffer, header.byteOffset, header.byteLength)
    .getBigUint64(0x118, true)
    .toString(16)
    .padStart(16, "0");
  if (u32(header, 0x180) < 0x400) throw new CtrFormatError("no extended header: not an executable partition");
  const exheader = exact(source, at + 0x200, 0x400, "extended header");
  const title = new TextDecoder("latin1").decode(exheader.subarray(0, 8)).replace(/\0+$/, "");
  const compressed = ((exheader[0xd] as number) & 1) === 1;

  const text = segment(exheader, 0x10, 0, "text");
  const rodata = segment(exheader, 0x20, text.pages * PAGE, "read-only data");
  const data = segment(exheader, 0x30, (text.pages + rodata.pages) * PAGE, "data");
  const end = data.offset + data.size;

  const exefsAt = at + u32(header, 0x1a0) * unit;
  const exefs = exact(source, exefsAt, 0x200, "ExeFS header");
  let code: Uint8Array | undefined;
  for (let i = 0; i < 10; i++) {
    const entry = exefs.subarray(i * 16, i * 16 + 16);
    const name = new TextDecoder("latin1").decode(entry.subarray(0, 8)).replace(/\0+$/, "");
    if (name === ".code") code = exact(source, exefsAt + 0x200 + u32(entry, 8), u32(entry, 12), ".code");
  }
  if (code === undefined) throw new CtrFormatError("the ExeFS has no .code");
  // The segments' pages bound the decompressed size, so a damaged footer cannot make the decoder allocate more.
  const raw = compressed ? blzDecompress(code, (text.pages + rodata.pages + data.pages) * PAGE) : code;
  if (raw.length < end) throw new CtrFormatError(`.code holds ${raw.length} bytes; its segments need ${end}`);
  const image = new Uint8Array(end);
  image.set(raw.subarray(0, end));
  const strip = ({ address, size, offset }: CodeSegment): CodeSegment => ({ address, size, offset });
  return {
    container,
    title,
    programId,
    image,
    base: text.address,
    text: strip(text),
    rodata: strip(rodata),
    data: strip(data),
  };
}

export function readCtrCode(source: ByteSource): CtrCode {
  const kind = ctrKind(source.read(0, 0x200));
  if (kind === "ncch") return readNcch(source, 0, "ncch");
  if (kind !== "ncsd") throw new CtrFormatError("neither NCSD nor NCCH");
  // Partition 0 of a card image is the executable content (CXI); its offset and size are in 0x200-byte units.
  const header = exact(source, 0, 0x200, "NCSD header");
  if (u32(header, 0x124) === 0) throw new CtrFormatError("partition 0 is empty");
  return readNcch(source, u32(header, 0x120) * 0x200, "ncsd");
}
