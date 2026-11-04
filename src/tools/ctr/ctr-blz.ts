// Decompresses the "bottom LZ" (BLZ) format of a 3DS application's ExeFS .code. The format is decoded from the end
// of the buffer towards its start: a footer gives the compressed region and the size gained, then control bytes
// and tokens are read backwards and the output is written backwards. Reference: the 3DS community documentation
// (3dbrew, "ExeFS") and ctrtool's lzss_decompress, which this follows step for step, bounds checks included.

export class BlzError extends Error {
  constructor(message: string) {
    super(`BLZ: ${message}`);
    this.name = "BlzError";
  }
}

/** Size of the data once decompressed, read from the footer. */
export function blzDecompressedSize(compressed: Uint8Array): number {
  if (compressed.length < 8) throw new BlzError("shorter than its footer");
  const view = new DataView(compressed.buffer, compressed.byteOffset, compressed.byteLength);
  return compressed.length + view.getUint32(compressed.length - 4, true);
}

export function blzDecompress(compressed: Uint8Array): Uint8Array {
  const size = compressed.length;
  const out = new Uint8Array(blzDecompressedSize(compressed));
  const view = new DataView(compressed.buffer, compressed.byteOffset, compressed.byteLength);
  const topAndBottom = view.getUint32(size - 8, true);
  let index = size - ((topAndBottom >>> 24) & 0xff);
  const stop = size - (topAndBottom & 0xffffff);
  if (stop < 0 || index > size || index < stop) throw new BlzError("footer points outside the data");
  out.set(compressed);
  let o = out.length;
  while (index > stop) {
    let control = compressed[--index] as number;
    for (let bit = 0; bit < 8; bit++) {
      if (index <= stop || index <= 0 || o <= 0) break;
      if (control & 0x80) {
        if (index < 2) throw new BlzError("token runs past the start");
        index -= 2;
        const token = (compressed[index] as number) | ((compressed[index + 1] as number) << 8);
        const length = ((token >>> 12) & 0xf) + 3;
        const offset = (token & 0x0fff) + 2;
        if (o < length) throw new BlzError("match runs past the start of the output");
        for (let j = 0; j < length; j++) {
          if (o + offset >= out.length) throw new BlzError("match refers past the end of the output");
          const value = out[o + offset] as number;
          out[--o] = value;
        }
      } else {
        if (o < 1) throw new BlzError("literal runs past the start of the output");
        out[--o] = compressed[--index] as number;
      }
      control = (control << 1) & 0xff;
    }
  }
  return out;
}
