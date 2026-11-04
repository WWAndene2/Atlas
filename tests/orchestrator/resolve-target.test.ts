import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { resolveTarget } from "../../src/orchestrator/resolve-target.js";
import { buildNcch, buildNcsd } from "../tools/ctr/ctr-builder.js";

const dir = mkdtempSync(join(tmpdir(), "atlas-resolve-"));

describe("resolveTarget", () => {
  it("passes an ordinary file to the engines as it is", async () => {
    const path = join(dir, "plain.bin");
    writeFileSync(path, new Uint8Array(0x400));
    const target = await resolveTarget(path);
    expect(target).toMatchObject({ input: { path }, label: "plain.bin" });
    expect(target.input.raw).toBeUndefined();
  });

  it("keeps the operator's raw description", async () => {
    const path = join(dir, "plain.bin");
    const raw = { architecture: "arm64" as const, base: "0x8000" };
    expect((await resolveTarget(path, raw)).input).toEqual({ path, raw });
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
    expect(target.label).toBe("game.3ds:code.bin");
    expect(target.input.raw).toEqual({ architecture: "arm-v6k", base: "0x100000" });
    expect(new Uint8Array(readFileSync(target.input.path))).toEqual(code);
    expect(target.container).toMatchObject({ container: "ncsd", base: "0x100000" });
    await target.dispose();
    expect(existsSync(dirname(target.input.path))).toBe(false);
  });
});
