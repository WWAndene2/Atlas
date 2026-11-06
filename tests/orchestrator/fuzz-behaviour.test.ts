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
    const found = store.getHypothesis(result.found[0]?.hypothesis as string);
    expect(found).toMatchObject({ kind: "behaviour", confidence: "observed", author: { agent: "fuzzer" } });
    expect((found?.value as { scenario: { stdin: string } }).scenario.stdin).toContain("9");
    store.close();
  }, 300_000);
});
