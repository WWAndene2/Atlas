import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { coverageBehaviour } from "../../src/orchestrator/coverage-behaviour.js";
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

// Two paths: an argument selects shout() or whisper(); a behaviour of each adds its own function.
const PROGRAM = `#include <stdio.h>
__attribute__((noinline)) void shout(void) { puts("HELLO"); }
__attribute__((noinline)) void whisper(void) { puts("hello"); }
__attribute__((noinline)) void never(void) { puts("never"); }
int main(int argc, char **argv) { if (argc > 1) shout(); else whisper(); return 0; }
`;

const FUNCTIONS = `
import cle, json, sys
o = cle.Loader(sys.argv[1], auto_load_libs=False, main_opts={"base_addr": 0}).main_object
seen = {s.relative_addr: s for s in o.symbols if s.is_function and s.size and not s.is_import}
print(json.dumps([{"address": a, "size": s.size, "name": s.name, "code": o.memory.load(a, s.size).hex()}
                  for a, s in sorted(seen.items())]))
`;

describe.runIf(python !== undefined)("coverageBehaviour", () => {
  it("measures which translated functions the recorded behaviours reach, and what each adds", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-coverage-test-"));
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
    const program = join(dir, "p");
    await recordBehaviour(store, program, { argv: [] });
    await recordBehaviour(store, program, { argv: ["loud"] });
    const report = await coverageBehaviour(store, program);
    const label = (a: string) => functions.find((f) => `0x${f.address.toString(16)}` === a)?.name;
    expect(report.behaviours.map((b) => b.added > 0)).toEqual([true, true]); // whisper, then shout
    expect(report.covered).toBeLessThan(report.translated);
    expect(report.uncovered.map((u) => label(u.address))).toContain("never");
    expect(report.uncovered.map((u) => label(u.address))).not.toContain("shout");
    store.close();
  }, 600_000);
});
