import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { blameBehaviour } from "../../src/orchestrator/blame-behaviour.js";
import { fileSha256 } from "../../src/orchestrator/file-hash.js";
import { binaryId } from "../../src/orchestrator/load-binary.js";
import { recordBehaviour } from "../../src/orchestrator/record-behaviour.js";
import { locateAngr } from "../../src/tools/angr/index.js";

function angr(): string | undefined {
  try {
    return locateAngr();
  } catch {
    return undefined;
  }
}
const python = angr();

const PROGRAM = `#include <stdio.h>
__attribute__((noinline)) int square(int x) { return x * x; }
__attribute__((noinline)) int twice(int x) { return 2 * x; }
int main(int argc, char **argv) { printf("%d %d\\n", square(argc + 6), twice(argc)); return 0; }
`;

const FUNCTIONS = `
import cle, json, sys
o = cle.Loader(sys.argv[1], auto_load_libs=False, main_opts={"base_addr": 0}).main_object
seen = {s.relative_addr: s for s in o.symbols if s.is_function and s.size and not s.is_import}
print(json.dumps([{"address": a, "size": s.size, "name": s.name, "code": o.memory.load(a, s.size).hex()}
                  for a, s in sorted(seen.items())]))
`;

describe.runIf(python !== undefined)("blameBehaviour", () => {
  it("names the one function whose rewrite makes a behaviour fail, by halving the native set", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-blame-test-"));
    writeFileSync(join(dir, "p.c"), PROGRAM);
    execFileSync("gcc", ["-O1", "-fcf-protection=none", "p.c", "-o", "p"], { cwd: dir });
    writeFileSync(join(dir, "functions.py"), FUNCTIONS);
    const functions = JSON.parse(
      execFileSync(python as string, ["-I", join(dir, "functions.py"), join(dir, "p")], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }),
    ) as { address: number; size: number; name: string; code: string }[];
    const store = new GraphStore(join(dir, "g.sqlite"));
    const binary = binaryId(await fileSha256(join(dir, "p")));
    store.putNode({ schema_version: 1, id: binary, kind: "binary", architecture: "x86_64" });
    for (const f of functions) {
      store.putNode({
        schema_version: 1,
        id: `fn_${f.address.toString(16)}`,
        kind: "function",
        binary,
        address: `0x${f.address.toString(16)}`,
        size: f.size,
        code: f.code,
        label: f.name,
      });
    }
    // main calls square, as atlas load records it: the edge that tells the faulty function from its caller.
    const id = (name: string) => `fn_${(functions.find((f) => f.name === name)?.address ?? 0).toString(16)}`;
    store.putEdge({ schema_version: 1, from: id("main"), to: id("square"), kind: "calls", evidence: [binary] });
    const program = join(dir, "p");
    const behaviour = (await recordBehaviour(store, program, { argv: [] })).hypothesis.id;
    // Nothing to blame while the rebuilt program reproduces the behaviour.
    expect((await blameBehaviour(store, program, behaviour)).result).toBe("reproduced");

    // A rewrite of square that compiles and passed its check, but returns the wrong value: the program fails.
    const square = id("square");
    store.proposeHypothesis({
      schema_version: 1,
      id: "hyp_00000000000000000001",
      node: binary,
      kind: "toolchain",
      value: {
        cc: "gcc",
        flags: ["-O1", "-fcf-protection=none"],
        verified: 1,
        closeness: 1,
        sample: 1,
        ties: [],
        clues: [],
      },
      confidence: "inferred",
      evidence: [binary],
      author: { agent: "test" },
    });
    store.proposeHypothesis({
      schema_version: 1,
      id: "hyp_00000000000000000002",
      node: square,
      kind: "rewrite",
      value: { language: "c", name: "square", source: "int square(int x) { return x + x; }\n" },
      confidence: "inferred",
      evidence: [square],
      author: { agent: "test" },
    });
    store.recordVerification("hyp_00000000000000000002", {
      confidence: "verified",
      verification: { check: "recompile", result: "pass", details: "test: a wrong rewrite taken as verified" },
    });
    const blame = await blameBehaviour(store, program, behaviour);
    expect(blame.result).toBe("blamed");
    // The smallest failing set: square's wrong rewrite and main, the translated caller that reaches it.
    expect(blame.culprits.map((c) => [c.label, c.rewritten, c.likely]).sort()).toEqual([
      ["main", false, false],
      ["square", true, true],
    ]);
    expect(blame.differences[0]).toMatch(/^stdout: first difference/);
    store.close();
  }, 1_800_000);
});
