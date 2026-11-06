import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { copyBehaviour } from "../../src/orchestrator/copy-behaviour.js";
import { fileSha256 } from "../../src/orchestrator/file-hash.js";
import { binaryId } from "../../src/orchestrator/load-binary.js";
import { recordBehaviour } from "../../src/orchestrator/record-behaviour.js";
import { replayBehaviour } from "../../src/orchestrator/replay-behaviour.js";

const PROGRAM = `#include <stdio.h>
int main(int argc, char **argv) { long s = 0; for (int i = 0; i < argc * 1000; i++) s += i % 7; printf("%ld\\n", s); return argc; }`;
const WRONG = `#include <stdio.h>
int main(int argc, char **argv) { printf("0\\n"); return argc; }`;

function build(dir: string, name: string, source: string, flags: string[]): string {
  writeFileSync(join(dir, `${name}.c`), source);
  execFileSync("gcc", [...flags, `${name}.c`, "-o", name], { cwd: dir });
  return join(dir, name);
}

describe("copyBehaviour", () => {
  it("carries one build's behaviours to another build, inferred until replayed there", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-copy-"));
    const store = new GraphStore(join(dir, "g.sqlite"));
    const reference = build(dir, "o0", PROGRAM, ["-O0"]);
    const target = build(dir, "o2", PROGRAM, ["-O2"]);
    for (const p of [reference, target]) {
      store.putNode({ schema_version: 1, id: binaryId(await fileSha256(p)), kind: "binary", architecture: "x86_64" });
    }
    await recordBehaviour(store, reference, { argv: [] });
    await recordBehaviour(store, reference, { argv: ["a", "b"] });
    const { copied } = await copyBehaviour(store, reference, target);
    expect(copied).toHaveLength(2);
    expect(store.getHypothesis(copied[0] as string)).toMatchObject({
      node: binaryId(await fileSha256(target)),
      confidence: "inferred",
      author: { agent: "copier" },
    });
    expect((await copyBehaviour(store, reference, target)).already).toBe(2);

    // A wrong program leaves the copies inferred; the target's own build reproduces them: verified.
    await replayBehaviour(store, target, build(dir, "wrong", WRONG, ["-O1"]));
    expect(store.getHypothesis(copied[0] as string)?.confidence).toBe("inferred");
    const replay = await replayBehaviour(store, target, target);
    expect(replay.results.map((r) => r.result)).toEqual(["pass", "pass"]);
    expect(store.getHypothesis(copied[1] as string)?.confidence).toBe("verified");
    store.close();
  }, 120_000);
});
