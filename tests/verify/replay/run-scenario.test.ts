import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import { decode, differences, encode, runScenario } from "../../../src/verify/replay/run-scenario.js";

// A program that shows each condition the runner sets: argv[0], an argument, an environment variable, its working
// directory's input file, its standard input; it writes an output file, a line to stderr, and exits 5.
const PROGRAM = `
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
  char line[64] = {0}, in[64] = {0};
  fgets(line, sizeof line, stdin);
  FILE *f = fopen("in.txt", "r"); if (f) { fgets(in, sizeof in, f); fclose(f); }
  printf("%s|%s|%s|%s|%s|%s", argv[0], argc > 1 ? argv[1] : "-", getenv("MODE") ? getenv("MODE") : "-",
         getenv("TZ"), in, line);
  f = fopen("out.bin", "wb"); fputc(0xff, f); fputc(0, f); fclose(f);
  fputs("warned\\n", stderr);
  return 5;
}
`;

function build(): string {
  const dir = mkdtempSync(join(tmpdir(), "atlas-replay-test-"));
  writeFileSync(join(dir, "p.c"), PROGRAM);
  execFileSync("gcc", ["-O1", "p.c", "-o", "p"], { cwd: dir });
  return join(dir, "p");
}

describe("runScenario", () => {
  it("runs the program in a fresh directory with the scenario's inputs, and keeps what it did", async () => {
    const outcome = await runScenario(build(), {
      argv: ["first"],
      stdin: "typed\n",
      env: { MODE: "fast" },
      inputs: [{ name: "in.txt", content: { text: "from file\n" } }],
      outputs: ["out.bin", "never.txt"],
    });
    expect(outcome.stdout).toEqual({ text: "program|first|fast|UTC|from file\n|typed\n" });
    expect(outcome.stderr).toEqual({ text: "warned\n" });
    expect(outcome.exit).toBe(5);
    // Bytes that are not UTF-8 are kept exactly, as base64; a file the program did not write is null.
    expect(outcome.files["out.bin"]).toEqual({ base64: Buffer.from([0xff, 0]).toString("base64") });
    expect(outcome.files["never.txt"]).toBeNull();
  }, 60_000);

  it("runs a program named by a path relative to where it is called from", async () => {
    const outcome = await runScenario(relative(process.cwd(), build()), { argv: [] });
    expect(outcome.exit).toBe(5);
  }, 60_000);

  it("stops a program at its time limit", async () => {
    const outcome = await runScenario("/bin/sh", { argv: ["-c", "sleep 30"], timeout_s: 1 });
    expect(outcome.exit).toBe("timeout");
  }, 30_000);

  it("refuses input and output names that are paths", async () => {
    await expect(
      runScenario("/bin/true", { argv: [], inputs: [{ name: "../x", content: { text: "" } }] }),
    ).rejects.toThrow(/a name, not a path/);
  });
});

describe("differences", () => {
  it("masks the parts that legitimately vary, and still sees every other difference", () => {
    const at = (t: string) => ({ stdout: { text: t }, stderr: { text: "" }, exit: 0, files: {} });
    const vary = ["\\d{10}"];
    expect(differences(at("time 1793900000 ok\n"), at("time 1793900042 ok\n"), vary)).toEqual([]);
    expect(differences(at("time 1793900000 ok\n"), at("time 1793900042 OK\n"), vary)).toEqual([
      "stdout: first difference at byte 14 (17 expected, 17 got)",
    ]);
    expect(differences(at("time 1793900000 ok\n"), at("time 1793900042 ok\n"))).toHaveLength(1);
  });

  it("names each part that differs, and nothing when the outcomes are the same", () => {
    const a = { stdout: encode(Buffer.from("abc")), stderr: { text: "" }, exit: 0, files: { f: { text: "x" } } };
    expect(differences(a, a)).toEqual([]);
    const b = { stdout: { text: "abd" }, stderr: { text: "" }, exit: 1, files: { f: null } };
    expect(differences(a, b)).toEqual([
      "stdout: first difference at byte 2 (3 expected, 3 got)",
      "exit: 0 expected, 1 got",
      "file f: written expected, not written got",
    ]);
    expect(decode({ base64: Buffer.from("é").toString("base64") }).toString()).toBe("é");
  });
});
