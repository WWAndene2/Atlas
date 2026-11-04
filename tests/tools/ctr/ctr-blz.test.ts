import { describe, expect, it } from "vitest";
import { BlzError, blzDecompress } from "../../../src/tools/ctr/index.js";
import { blzCompress } from "./ctr-builder.js";

function sample(size: number): Uint8Array {
  // Code-like data: repeated structure with variation, so both literals and matches occur.
  const out = new Uint8Array(size);
  let seed = 12345;
  for (let i = 0; i < size; i++) {
    seed = (seed * 1103515245 + 12345) >>> 0;
    out[i] = i % 64 < 40 ? (i * 7) & 0xff : seed >>> 24;
  }
  return out;
}

describe("BLZ", () => {
  it("restores compressed data exactly", () => {
    for (const size of [512, 1000, 65536]) {
      const data = sample(size);
      const packed = blzCompress(data);
      expect(packed.length).toBeLessThan(data.length);
      expect(blzDecompress(packed)).toEqual(data);
    }
  });

  it("refuses a footer pointing outside the data", () => {
    const packed = blzCompress(sample(1000));
    new DataView(packed.buffer).setUint32(packed.length - 8, (8 << 24) | (packed.length + 100), true);
    expect(() => blzDecompress(packed)).toThrow(BlzError);
    expect(() => blzDecompress(new Uint8Array(4))).toThrow(BlzError);
  });
});
