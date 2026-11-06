import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { fileSha256 } from "../../src/orchestrator/file-hash.js";
import { fuzzBehaviour } from "../../src/orchestrator/fuzz-behaviour.js";
import { binaryId } from "../../src/orchestrator/load-binary.js";
import { recordBehaviour } from "../../src/orchestrator/record-behaviour.js";

function build(dir: string, name: string, source: string): string {
  writeFileSync(join(dir, `${name}.c`), source);
  execFileSync("gcc", ["-O1", `${name}.c`, "-o", name], { cwd: dir });
  return join(dir, name);
}

// The original counts the digits of its input; the "reconstruction" agrees except on inputs holding a 9.
const ORIGINAL = `#include <stdio.h>
int main(void) { int c, n = 0; while ((c = getchar()) != EOF) n += c >= '0' && c <= '9'; printf("%d\\n", n); return 0; }`;
const RECONSTRUCTION = `#include <stdio.h>
int main(void) { int c, n = 0; while ((c = getchar()) != EOF) n += c >= '0' && c <= '8'; printf("%d\\n", n); return 0; }`;

describe("fuzzBehaviour", () => {
  it("finds an input on which the reconstruction differs from the original, and records it as a behaviour", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-fuzz-"));
    const store = new GraphStore(join(dir, "g.sqlite"));
    const original = build(dir, "original", ORIGINAL);
    const binary = binaryId(await fileSha256(original));
    store.putNode({ schema_version: 1, id: binary, kind: "binary", architecture: "x86_64" });
    await recordBehaviour(store, original, { argv: [], stdin: "a1b2c3 0123456788" });
    const result = await fuzzBehaviour(store, original, build(dir, "rebuilt", RECONSTRUCTION), {
      rounds: 200,
      seed: 3,
      limit: 1,
    });
    expect(result.found).toHaveLength(1);
    expect(result.covered).toBeUndefined(); // a plain gcc build writes no ATLAS_COVERAGE
    const found = store.getHypothesis(result.found[0]?.hypothesis as string);
    expect(found).toMatchObject({ kind: "behaviour", confidence: "observed", author: { agent: "fuzzer" } });
    expect((found?.value as { scenario: { stdin: string } }).scenario.stdin).toContain("9");
    store.close();
  }, 300_000);
});

// A reconstruction that reports coverage as the linked programs do (ATLAS_COVERAGE, one address per line at exit):
// one "function" per kind of byte its input holds. It agrees with the original, so only coverage changes.
const COVERING = `#include <stdio.h>
#include <stdlib.h>
int main(void) {
  int c, n = 0, seen[4] = {0};
  while ((c = getchar()) != EOF) {
    n += c >= '0' && c <= '9';
    seen[c >= '0' && c <= '9' ? 0 : c >= 'a' && c <= 'z' ? 1 : c == ' ' || c == '\\n' ? 2 : 3] = 1;
  }
  printf("%d\\n", n);
  const char *out = getenv("ATLAS_COVERAGE");
  if (out) { FILE *f = fopen(out, "w"); for (int k = 0; k < 4; k++) if (seen[k]) fprintf(f, "%#x\\n", 0x1000 + k); fclose(f); }
  return 0;
}`;

describe("fuzzBehaviour coverage guidance", () => {
  it("keeps as seeds the mutants that reach code no earlier run reached", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-fuzz-guided-"));
    const store = new GraphStore(join(dir, "g.sqlite"));
    const original = build(dir, "original", ORIGINAL);
    const binary = binaryId(await fileSha256(original));
    store.putNode({ schema_version: 1, id: binary, kind: "binary", architecture: "x86_64" });
    await recordBehaviour(store, original, { argv: [], stdin: "abc" });
    const result = await fuzzBehaviour(store, original, build(dir, "covering", COVERING), { rounds: 60, seed: 5 });
    expect(result.found).toEqual([]);
    expect(result.seeded).toBeGreaterThan(0);
    expect(result.covered).toBeGreaterThan(1);
    store.close();
  }, 300_000);
});
