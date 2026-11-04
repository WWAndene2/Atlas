import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { resolveTarget, type ResolvedBinary } from "../../src/orchestrator/resolve-target.js";
import { buildNcch, buildNcsd } from "../tools/ctr/ctr-builder.js";
import { buildZip } from "../tools/zip/zip-builder.js";

const dir = mkdtempSync(join(tmpdir(), "atlas-resolve-"));

describe("resolveTarget", () => {
  it("passes an ordinary file to the engines as it is", async () => {
    const path = join(dir, "plain.bin");
    writeFileSync(path, new Uint8Array(0x400));
    const target = await resolveTarget(path);
    expect(target.binaries).toEqual([{ input: { path }, label: "plain.bin" }]);
  });

  it("keeps the operator's raw description", async () => {
    const path = join(dir, "plain.bin");
    const raw = { architecture: "arm64" as const, base: "0x8000" };
    expect((await resolveTarget(path, raw)).binaries[0]?.input).toEqual({ path, raw });
  });

  it("opens a 3DS card image into its code, as a raw ARMv6K image at the text address", async () => {
    const code = new Uint8Array(0x2000).map((_, i) => (i * 5) & 0xff);
    const path = join(dir, "game.3ds");
    writeFileSync(
      path,
      buildNcsd(
        buildNcch({
          code,
          text: { address: 0x100000, pages: 2, size: 0x2000 },
          rodata: { address: 0x102000, pages: 0, size: 0 },
          data: { address: 0x102000, pages: 0, size: 0 },
          compress: true,
        }),
      ),
    );
    const target = await resolveTarget(path);
    const [binary] = target.binaries;
    expect(binary?.label).toBe("game.3ds:code.bin");
    expect(binary?.input.raw).toEqual({ architecture: "arm-v6k", base: "0x100000" });
    expect(new Uint8Array(readFileSync((binary as ResolvedBinary).input.path))).toEqual(code);
    expect(target.container).toMatchObject({ format: "3ds", code: { container: "ncsd", base: "0x100000" } });
    await target.dispose();
    expect(existsSync(dirname((binary as ResolvedBinary).input.path))).toBe(false);
  });

  it("opens a package into each executable it holds", async () => {
    const elf = new Uint8Array(64);
    elf.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1]);
    const dex = new TextEncoder().encode("dex\n035\0" + "x".repeat(100));
    const path = join(dir, "app.apk");
    writeFileSync(
      path,
      buildZip([
        { name: "AndroidManifest.xml", data: new TextEncoder().encode("<manifest/>"), deflate: true },
        { name: "lib/arm64-v8a/libgame.so", data: elf, deflate: true },
        { name: "classes.dex", data: dex, deflate: false },
        { name: "assets/../../evil.so", data: elf, deflate: false },
      ]),
    );
    const target = await resolveTarget(path);
    expect(target.binaries.map((b) => b.label)).toEqual([
      "app.apk:lib/arm64-v8a/libgame.so",
      "app.apk:classes.dex",
      "app.apk:assets/../../evil.so",
    ]);
    // A member's path never becomes a path on disk.
    for (const b of target.binaries)
      expect(dirname(b.input.path)).toBe(dirname((target.binaries[0] as ResolvedBinary).input.path));
    expect(new Uint8Array(readFileSync((target.binaries[0] as ResolvedBinary).input.path))).toEqual(elf);
    expect(target.container).toEqual({ format: "zip", members: 4 });
    await target.dispose();
  });
});
