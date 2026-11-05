import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { locateAngr } from "../../../src/tools/angr/index.js";
import { liftFunctions, RUNTIME_HEADER } from "../../../src/tools/vex/index.js";

function angr(): string | undefined {
  try {
    return locateAngr();
  } catch {
    return undefined;
  }
}
const python = angr();

describe.runIf(python !== undefined)("liftFunctions", () => {
  it("translates x86-64 code to C that computes what the original computes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-lift-test-"));
    // Branches, a loop, a signed comparison, a multiply and a memory read: flags, loads and dispatch exercised.
    const source =
      "long f(const int *p, long n, long k){long s=0;for(long i=0;i<n;i++){if(p[i]>k)s+=p[i]*3;else s-=1;}return s;}";
    writeFileSync(join(dir, "f.c"), source);
    execFileSync("gcc", ["-O2", "-fcf-protection=none", "-ffunction-sections", "-c", "f.c", "-o", "f.o"], { cwd: dir });
    execFileSync("objcopy", ["-O", "binary", "--only-section=.text.f", "f.o", "f.bin"], { cwd: dir });
    const code = readFileSync(join(dir, "f.bin")).toString("hex");
    const [lifted] = await liftFunctions(python as string, "x86_64", [{ address: 0x1000, code }]);
    expect(lifted && "c" in lifted).toBe(true);
    // A harness: flat guest memory, the array at 0x2000, the stack at 0x8000 with a return address, then the
    // result in rax compared with the original C's.
    writeFileSync(
      join(dir, "harness.c"),
      `#include "atlas_lift.h"
#include <stdio.h>
#include <stdlib.h>
${(lifted as { c: string }).c}
void atlas_call(atlas_state *s, uint64_t t) { if (t == 0x1000) fn_1000(s); else exit(3); }
void atlas_trap(atlas_state *s, uint64_t at, int k) { exit(4); }
${source}
int main(void) {
  static atlas_state st; atlas_state *s = &st; s->mem = calloc(1, 0x10000);
  int data[6] = {5, -2, 9, 0, 7, -8};
  memcpy(s->mem + 0x2000, data, sizeof data);
  for (long k = -3; k < 10; k++) {
    REG(uint64_t, 72) = 0x2000; REG(uint64_t, 64) = 6; REG(uint64_t, 32) = (uint64_t)k; /* rdi rsi rdx */
    REG(uint64_t, 48) = 0x8000; STORE64(0x8000, 0xdead);                                 /* rsp */
    fn_1000(s);
    if ((long)REG(uint64_t, 16) != f(data, 6, k)) { printf("k=%ld: %ld vs %ld\\n", k, (long)REG(uint64_t, 16), f(data, 6, k)); return 1; }
  }
  return 0;
}
`,
    );
    execFileSync("gcc", ["-O1", "-w", "-I", dirname(RUNTIME_HEADER), "harness.c", "-o", "harness"], { cwd: dir });
    expect(() => execFileSync(join(dir, "harness"))).not.toThrow();
  }, 120_000);
  it("reports what it cannot translate instead of translating it wrong", async () => {
    // fprem (x87 partial remainder), then ret: x87 register-stack access the translator does not implement.
    const [lifted] = await liftFunctions(python as string, "x86_64", [{ address: 0x1000, code: "d9f8c3" }]);
    expect(lifted).toMatchObject({ address: "0x1000", unsupported: expect.any(String) });
  }, 60_000);
});
