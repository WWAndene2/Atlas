// Random access to a target's bytes without loading the whole file: game images and packages are often larger than
// the 2 GiB a single Node.js read can return, and a reader needs only some headers and the parts that hold code.
import { closeSync, fstatSync, openSync, readSync } from "node:fs";

export interface ByteSource {
  readonly size: number;
  /** The bytes at [offset, offset + length), or fewer at the end of the source. */
  read(offset: number, length: number): Uint8Array;
}

export function bytesSource(bytes: Uint8Array): ByteSource {
  return { size: bytes.length, read: (offset, length) => bytes.subarray(offset, offset + length) };
}

/** A file opened for reading; close it when done. */
export function fileSource(path: string): ByteSource & { close(): void } {
  const fd = openSync(path, "r");
  const size = fstatSync(fd).size;
  return {
    size,
    read(offset, length) {
      const want = Math.max(0, Math.min(length, size - offset));
      const buffer = new Uint8Array(want);
      let done = 0;
      while (done < want) {
        const n = readSync(fd, buffer, done, want - done, offset + done);
        if (n === 0) break;
        done += n;
      }
      return buffer.subarray(0, done);
    },
    close: () => closeSync(fd),
  };
}
