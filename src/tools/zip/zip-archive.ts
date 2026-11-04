// Reads the members of a ZIP archive: the container of Android packages (.apk, .aab), iOS packages (.ipa), Java
// archives (.jar) and many game data files. Follows the ZIP application note (PKWARE APPNOTE): the end-of-central-
// directory record locates the central directory, whose entries give each member's local header; members are stored
// (method 0) or deflated (method 8). ZIP64 and encrypted members are reported, not read.
import { inflateRawSync } from "node:zlib";

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
  /** Reads the member's bytes. */
  read(): Uint8Array;
}

const EOCD = 0x06054b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;

export function isZip(bytes: Uint8Array): boolean {
  return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
}

export function zipMembers(bytes: Uint8Array): ZipMember[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // The end record sits in the last 22 bytes plus a comment of up to 65,535 bytes.
  let end = -1;
  for (let at = bytes.length - 22; at >= Math.max(0, bytes.length - 22 - 0xffff); at--) {
    if (view.getUint32(at, true) === EOCD) {
      end = at;
      break;
    }
  }
  if (end < 0) throw new ZipError("no end-of-central-directory record");
  const count = view.getUint16(end + 10, true);
  let at = view.getUint32(end + 16, true);
  if (count === 0xffff || at === 0xffffffff) throw new ZipError("ZIP64 archives are not read yet");
  const members: ZipMember[] = [];
  const decoder = new TextDecoder("utf-8");
  for (let i = 0; i < count; i++) {
    if (at + 46 > bytes.length || view.getUint32(at, true) !== CENTRAL) throw new ZipError("damaged central directory");
    const flags = view.getUint16(at + 8, true);
    const method = view.getUint16(at + 10, true);
    const compressedSize = view.getUint32(at + 20, true);
    const size = view.getUint32(at + 24, true);
    const nameLength = view.getUint16(at + 28, true);
    const extraLength = view.getUint16(at + 30, true);
    const commentLength = view.getUint16(at + 32, true);
    const local = view.getUint32(at + 42, true);
    const name = decoder.decode(bytes.subarray(at + 46, at + 46 + nameLength));
    at += 46 + nameLength + extraLength + commentLength;
    if (name.endsWith("/")) continue;
    members.push({
      name,
      size,
      read() {
        if ((flags & 1) !== 0) throw new ZipError(`${name} is encrypted`);
        if (local + 30 > bytes.length || view.getUint32(local, true) !== LOCAL)
          throw new ZipError(`${name}: bad header`);
        const start = local + 30 + view.getUint16(local + 26, true) + view.getUint16(local + 28, true);
        if (start + compressedSize > bytes.length) throw new ZipError(`${name} lies past the end of the archive`);
        const data = bytes.subarray(start, start + compressedSize);
        if (method === 0) return data;
        if (method === 8) return new Uint8Array(inflateRawSync(data, { maxOutputLength: size }));
        throw new ZipError(`${name}: compression method ${method} is not read`);
      },
    });
  }
  return members;
}
