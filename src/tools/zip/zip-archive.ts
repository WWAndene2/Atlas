// Reads the members of a ZIP archive: the container of Android packages (.apk, .aab), iOS packages (.ipa), Java
// archives (.jar) and many game data files. Follows the ZIP application note (PKWARE APPNOTE): the end-of-central-
// directory record locates the central directory, whose entries give each member's local header; members are stored
// (method 0) or deflated (method 8). ZIP64 and encrypted members are reported, not read. The archive is read by
// offset, so a package of several gigabytes costs only its directory and the members actually read.
import { constants, inflateRawSync } from "node:zlib";
import type { ByteSource } from "../byte-source.js";

export class ZipError extends Error {
  constructor(message: string) {
    super(`ZIP: ${message}`);
    this.name = "ZipError";
  }
}

export interface ZipMember {
  /** Path inside the archive, as stored (untrusted target data). */
  name: string;
  size: number;
  /** The member's bytes. Throws ZipError if they cannot be read. */
  read(): Uint8Array;
  /** The first bytes of the member (up to `length`), decompressing no more than needed. */
  peek(length: number): Uint8Array;
}

const EOCD = 0x06054b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;

export function isZip(bytes: Uint8Array): boolean {
  return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
}

function view(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

export function zipMembers(source: ByteSource): ZipMember[] {
  // The end record sits in the last 22 bytes plus a comment of up to 65,535 bytes.
  const tailStart = Math.max(0, source.size - 22 - 0xffff);
  const tail = source.read(tailStart, source.size - tailStart);
  const tv = view(tail);
  let end = -1;
  for (let at = tail.length - 22; at >= 0; at--) {
    if (tv.getUint32(at, true) === EOCD) {
      end = at;
      break;
    }
  }
  if (end < 0) throw new ZipError("no end-of-central-directory record");
  const count = tv.getUint16(end + 10, true);
  const directorySize = tv.getUint32(end + 12, true);
  const directoryAt = tv.getUint32(end + 16, true);
  if (count === 0xffff || directoryAt === 0xffffffff) throw new ZipError("ZIP64 archives are not read yet");
  if (directoryAt + directorySize > source.size) throw new ZipError("central directory lies past the end");
  const directory = source.read(directoryAt, directorySize);
  const dv = view(directory);
  const members: ZipMember[] = [];
  const decoder = new TextDecoder("utf-8");
  let at = 0;
  for (let i = 0; i < count; i++) {
    if (at + 46 > directory.length || dv.getUint32(at, true) !== CENTRAL)
      throw new ZipError("damaged central directory");
    const flags = dv.getUint16(at + 8, true);
    const method = dv.getUint16(at + 10, true);
    const compressedSize = dv.getUint32(at + 20, true);
    const size = dv.getUint32(at + 24, true);
    const nameLength = dv.getUint16(at + 28, true);
    const extraLength = dv.getUint16(at + 30, true);
    const commentLength = dv.getUint16(at + 32, true);
    const local = dv.getUint32(at + 42, true);
    const name = decoder.decode(directory.subarray(at + 46, at + 46 + nameLength));
    at += 46 + nameLength + extraLength + commentLength;
    if (name.endsWith("/")) continue;

    const dataStart = (): number => {
      if ((flags & 1) !== 0) throw new ZipError(`${name} is encrypted`);
      const header = source.read(local, 30);
      if (header.length < 30 || view(header).getUint32(0, true) !== LOCAL) throw new ZipError(`${name}: bad header`);
      const start = local + 30 + view(header).getUint16(26, true) + view(header).getUint16(28, true);
      if (start + compressedSize > source.size) throw new ZipError(`${name} lies past the end of the archive`);
      if (method !== 0 && method !== 8) throw new ZipError(`${name}: compression method ${method} is not read`);
      return start;
    };
    const inflate = (data: Uint8Array, limit: number, partial: boolean): Uint8Array => {
      try {
        return new Uint8Array(
          inflateRawSync(data, {
            maxOutputLength: Math.max(limit, 1),
            ...(partial ? { finishFlush: constants.Z_SYNC_FLUSH } : {}),
          }),
        );
      } catch (error) {
        throw new ZipError(`${name}: ${(error as Error).message}`);
      }
    };
    members.push({
      name,
      size,
      read() {
        const data = source.read(dataStart(), compressedSize);
        return method === 0 ? data : inflate(data, size, false);
      },
      peek(length) {
        const start = dataStart();
        if (method === 0) return source.read(start, Math.min(length, compressedSize));
        // A deflate stream's first bytes need only its first blocks: inflate a 64 KiB prefix, flushing what it yields
        // (at most about 64 MiB even at deflate's highest ratio).
        const prefix = source.read(start, Math.min(compressedSize, 64 * 1024));
        return inflate(prefix, 0x4000000, true).subarray(0, length);
      },
    });
  }
  return members;
}
