import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { locateFrida, traceProgram } from "../../../src/tools/frida/index.js";

function frida(): string | undefined {
  try {
    return locateFrida();
  } catch {
    return undefined;
  }
}
const python = frida();

describe.runIf(python !== undefined)("traceProgram", () => {
  it("counts calls and tells pointer arguments from integers, at the binary's own addresses", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-frida-test-"));
    writeFileSync(
      join(dir, "p.c"),
      `#include <stdio.h>
#include <string.h>
__attribute__((noinline)) int count(const char *s){return (int)strlen(s);}
__attribute__((noinline)) long scale(long a,long b){volatile long r=a*b;return r+(long)strlen("xyz");}
int main(int c,char**v){long t=0;for(int i=0;i<c;i++)t=scale(t+count(v[i]),3);printf("%ld\\n",t);return 0;}`,
    );
    execFileSync("gcc", ["-O2", "-pie", "-fPIE", "p.c", "-o", "p"], { cwd: dir });
    const symbols = execFileSync("nm", [join(dir, "p")], { encoding: "utf8" });
    const at = (name: string) => parseInt(new RegExp(`^([0-9a-f]+) T ${name}$`, "m").exec(symbols)?.[1] ?? "0", 16);
    const result = await traceProgram(python as string, {
      program: join(dir, "p"),
      argv: ["hello", "x"],
      functions: [at("count"), at("scale")],
    });
    expect(result.exit).toBe("exited");
    const count = result.functions[`0x${at("count").toString(16)}`];
    const scale = result.functions[`0x${at("scale").toString(16)}`];
    expect(count?.calls).toBe(3);
    expect(count?.args[0]).toMatchObject({ pointer: 3, integer: 0 });
    expect(scale?.calls).toBe(3);
    expect(scale?.args[1]).toMatchObject({ pointer: 0, integer: 3 });
  }, 60_000);
});
