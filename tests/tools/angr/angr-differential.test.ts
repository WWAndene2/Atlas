import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { locateAngr, runDifferential } from "../../../src/tools/angr/index.js";

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
  return runDifferential(
    python as string,
    { code: compile(...a), address: 0x400000 },
    { code: compile(...b), address: 0x500000 },
    { inputs: 20, buffer: 64 },
  );
}

describe.runIf(python !== undefined)("runDifferential", () => {
  it("runs to the end the loops the symbolic check gives up on", async () => {
    const loop = "int f(int*p,int n){int s=0;for(int i=0;i<n;i++)s+=p[i];return s;}";
    expect((await compare([loop, ["-O2"]], [loop, ["-O0"]])).result).toBe("same");
  }, 240_000);
  it("finds a difference in a buffer, with the input", async () => {
    const answer = await compare(["void f(int*p,int v){p[1]=v;}", ["-O2"]], ["void f(int*p,int v){p[2]=v;}", ["-O2"]]);
    expect(answer.result).toBe("different");
    expect(answer.details).toContain("buf0");
  }, 240_000);
  it("answers inconclusive for calls", async () => {
    const call = "int g(int);int f(int x){return g(x)+1;}";
    expect((await compare([call, ["-O2"]], [call, ["-O0"]])).result).toBe("inconclusive");
  }, 120_000);
});
