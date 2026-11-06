import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkEquivalence, locateAngr } from "../../../src/tools/angr/index.js";

function angr(): string | undefined {
  try {
    return locateAngr();
  } catch {
    return undefined;
  }
}
const python = angr();

/** Machine code of `f` compiled with gcc and the given flags. */
function compile(source: string, flags: string[]): Uint8Array {
  const dir = mkdtempSync(join(tmpdir(), "atlas-eq-test-"));
  writeFileSync(join(dir, "t.c"), source);
  execFileSync("gcc", [...flags, "-fcf-protection=none", "-ffunction-sections", "-c", "t.c", "-o", "t.o"], {
    cwd: dir,
  });
  execFileSync("objcopy", ["-O", "binary", "--only-section=.text.f", "t.o", "t.bin"], { cwd: dir });
  return readFileSync(join(dir, "t.bin"));
}

async function compare(a: [string, string[]], b: [string, string[]]) {
  return checkEquivalence(
    python as string,
    { code: compile(...a), address: 0x400000 },
    { code: compile(...b), address: 0x500000 },
    { maxSteps: 200, buffer: 64 },
  );
}

describe.runIf(python !== undefined)("checkEquivalence", () => {
  const f8 = "int f(int x){return x*8+3;}";
  it("finds -O0 and -O2 builds of one function equivalent", async () => {
    expect((await compare([f8, ["-O0"]], [f8, ["-O2"]])).result).toBe("equivalent");
  }, 120_000);
  it("finds a changed constant different, with a counterexample", async () => {
    const answer = await compare([f8, ["-O2"]], ["int f(int x){return x*8+4;}", ["-O2"]]);
    expect(answer.result).toBe("different");
    expect(answer.counterexample).toHaveProperty("arg0");
  }, 120_000);
  it("tells branches apart", async () => {
    const max = "int f(int a,int b){return a>b?a:b;}";
    expect((await compare([max, ["-O2"]], ["int f(int a,int b){if(a<=b)return b;return a;}", ["-O0"]])).result).toBe(
      "equivalent",
    );
    expect((await compare([max, ["-O2"]], ["int f(int a,int b){return a>=b?b:a;}", ["-O2"]])).result).toBe("different");
  }, 240_000);
  it("compares what is read and written through pointers", async () => {
    expect(
      (
        await compare(
          ["int f(int*p){return p[0]+p[2];}", ["-O2"]],
          ["int f(int*p){int s=p[2];return s+p[0];}", ["-O0"]],
        )
      ).result,
    ).toBe("equivalent");
    expect(
      (await compare(["void f(int*p,int v){p[1]=v;}", ["-O2"]], ["void f(int*p,int v){p[2]=v;}", ["-O2"]])).result,
    ).toBe("different");
  }, 240_000);
  it("answers inconclusive for calls and unbounded loops", async () => {
    const call = "int g(int);int f(int x){return g(x)+1;}";
    expect((await compare([call, ["-O2"]], [call, ["-O0"]])).result).toBe("inconclusive");
    const loop = "int f(int*p,int n){int s=0;for(int i=0;i<n;i++)s+=p[i];return s;}";
    expect((await compare([loop, ["-O2"]], [loop, ["-O0"]])).result).toBe("inconclusive");
  }, 240_000);
});
