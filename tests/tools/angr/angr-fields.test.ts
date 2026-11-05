import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { functionFields, locateAngr } from "../../../src/tools/angr/index.js";

function angr(): string | undefined {
  try {
    return locateAngr();
  } catch {
    return undefined;
  }
}
const python = angr();

describe.runIf(python !== undefined)("functionFields", () => {
  it("finds the offsets and widths read and written through a pointer argument, callees included", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-fields-test-"));
    writeFileSync(
      join(dir, "p.c"),
      `struct s { int a; long b; char c; short d; };
__attribute__((noinline)) static void bump(struct s *p) { p->d += 1; }
__attribute__((noinline)) long use(struct s *p, long k) { bump(p); p->c = (char)k; return p->a + p->b; }
int main(void) { struct s v = {1, 2, 3, 4}; return (int)use(&v, 5); }`,
    );
    execFileSync("gcc", ["-O2", "-fPIE", "-pie", "p.c", "-o", "p"], { cwd: dir });
    const at = parseInt(
      /^([0-9a-f]+) T use$/m.exec(execFileSync("nm", [join(dir, "p")], { encoding: "utf8" }))?.[1] ?? "0",
      16,
    );
    const found = await functionFields(python as string, join(dir, "p"), [at], { positionIndependent: true });
    const fields = found[`0x${at.toString(16)}`]?.args["0"] ?? [];
    expect(fields.map((f) => [f.offset, f.size])).toEqual([
      [0, 4],
      [8, 8],
      [16, 1],
      [18, 2],
    ]);
    expect(fields.find((f) => f.offset === 16)).toMatchObject({ write: true });
    expect(fields.find((f) => f.offset === 18)).toMatchObject({ read: true, write: true });
    expect(found[`0x${at.toString(16)}`]?.args["1"]).toBeUndefined();
  }, 120_000);
});
