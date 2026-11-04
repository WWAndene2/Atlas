// Test helpers: a BLZ encoder and a minimal 3DS container builder, the mirror of what src/tools/ctr/ reads, written
// from the same documentation. They make test inputs only; a round trip through them shows the reader is
// consistent with the documented layout, not that it matches every real dump.

/** BLZ-compresses data: greedy matches of 3 to 18 bytes at distances 3 to 4098, in the format's reversed order. */
export function blzCompress(data: Uint8Array): Uint8Array {
  const n = data.length;
  const r = Uint8Array.from(data).reverse();
  const stream: number[] = [];
  const recent = new Map<number, number[]>();
  const key = (k: number): number => ((r[k] as number) << 16) | ((r[k + 1] as number) << 8) | (r[k + 2] as number);
  let k = 0;
  while (k < n) {
    const controlAt = stream.length;
    stream.push(0);
    let control = 0;
    for (let bit = 0; bit < 8 && k < n; bit++) {
      let bestLength = 0;
      let bestDistance = 0;
      if (k + 3 <= n) {
        for (const from of recent.get(key(k)) ?? []) {
          const distance = k - from;
          if (distance < 3 || distance > 4098) continue;
          let length = 0;
          while (length < 18 && k + length < n && r[k + length] === r[k + length - distance]) length++;
          if (length > bestLength) [bestLength, bestDistance] = [length, distance];
        }
      }
      const step = bestLength >= 3 ? bestLength : 1;
      if (bestLength >= 3) {
        control |= 0x80 >> bit;
        const token = ((bestLength - 3) << 12) | (bestDistance - 3);
        stream.push(token >> 8, token & 0xff);
      } else {
        stream.push(r[k] as number);
      }
      for (let i = k; i < k + step && i + 3 <= n; i++) {
        const list = recent.get(key(i)) ?? [];
        list.push(i);
        if (list.length > 16) list.shift();
        recent.set(key(i), list);
      }
      k += step;
    }
    stream[controlAt] = control;
  }
  const size = stream.length + 8;
  if (size > n) throw new Error("data does not compress; real tools would store it uncompressed");
  const out = new Uint8Array(size);
  stream.forEach((byte, j) => (out[stream.length - 1 - j] = byte));
  const view = new DataView(out.buffer);
  view.setUint32(size - 8, (8 << 24) | size, true);
  view.setUint32(size - 4, n - size, true);
  return out;
}

export interface Segment {
  address: number;
  pages: number;
  size: number;
}

export interface ContainerOptions {
  code: Uint8Array;
  text: Segment;
  rodata: Segment;
  data: Segment;
  compress: boolean;
  encrypted?: boolean;
  title?: string;
}

const unit = 0x200;
const pad = (size: number): number => Math.ceil(size / unit) * unit;

export function buildNcch(o: ContainerOptions): Uint8Array {
  const code = o.compress ? blzCompress(o.code) : o.code;
  const exefsOffset = 0xa00;
  const exefsSize = pad(0x200 + code.length);
  const ncch = new Uint8Array(exefsOffset + exefsSize);
  const view = new DataView(ncch.buffer);
  ncch.set(new TextEncoder().encode("NCCH"), 0x100);
  view.setUint32(0x104, ncch.length / unit, true);
  view.setBigUint64(0x118, 0x0004000000123400n, true);
  view.setUint32(0x180, 0x400, true);
  ncch[0x188 + 7] = o.encrypted === true ? 0 : 0x04;
  view.setUint32(0x1a0, exefsOffset / unit, true);
  view.setUint32(0x1a4, exefsSize / unit, true);
  ncch.set(new TextEncoder().encode(o.title ?? "ATLASTST"), 0x200);
  ncch[0x200 + 0xd] = o.compress ? 1 : 0;
  for (const [at, s] of [
    [0x210, o.text],
    [0x220, o.rodata],
    [0x230, o.data],
  ] as const) {
    view.setUint32(at, s.address, true);
    view.setUint32(at + 4, s.pages, true);
    view.setUint32(at + 8, s.size, true);
  }
  ncch.set(new TextEncoder().encode(".code"), exefsOffset);
  view.setUint32(exefsOffset + 8, 0, true);
  view.setUint32(exefsOffset + 12, code.length, true);
  ncch.set(code, exefsOffset + 0x200);
  return ncch;
}

export function buildNcsd(ncch: Uint8Array): Uint8Array {
  const partitionOffset = 0x4000;
  const out = new Uint8Array(partitionOffset + ncch.length);
  const view = new DataView(out.buffer);
  out.set(new TextEncoder().encode("NCSD"), 0x100);
  view.setUint32(0x104, out.length / unit, true);
  view.setUint32(0x120, partitionOffset / unit, true);
  view.setUint32(0x124, ncch.length / unit, true);
  out.set(ncch, partitionOffset);
  return out;
}
