import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { checkReconstruction } from "../../src/orchestrator/check-reconstruction.js";
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
#include <stdlib.h>
static int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
int main(int argc, char **argv) { int n = argc > 1 ? atoi(argv[1]) : 10; printf("fib %d = %d\\n", n, fib(n)); return n % 7; }
`;

// The program's functions as a load puts them in the graph (address, size, code), from its symbol table: the step
// under test starts from a loaded graph, which an engine would otherwise build.
const FUNCTIONS = `
import cle, json, sys
o = cle.Loader(sys.argv[1], auto_load_libs=False, main_opts={"base_addr": 0}).main_object
print(json.dumps([{"address": s.relative_addr, "size": s.size, "code": o.memory.load(s.relative_addr, s.size).hex()}
                  for s in o.symbols if s.is_function and s.size and not s.is_import]))
`;

describe.runIf(python !== undefined)("checkReconstruction", () => {
  it("rebuilds the program and replays its recorded behaviours, or does nothing when none is recorded", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-reconstruction-test-"));
    writeFileSync(join(dir, "p.c"), PROGRAM);
    execFileSync("gcc", ["-O1", "-fcf-protection=none", "p.c", "-o", "p"], { cwd: dir });
    writeFileSync(join(dir, "functions.py"), FUNCTIONS);
    const functions = JSON.parse(
      execFileSync(python as string, ["-I", join(dir, "functions.py"), join(dir, "p")], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }),
    ) as { address: number; size: number; code: string }[];
    const store = new GraphStore(join(dir, "g.sqlite"));
    const binary = binaryId(await fileSha256(join(dir, "p")));
    store.putNode({ schema_version: 1, id: binary, kind: "binary", architecture: "x86_64" });
    for (const f of functions) {
      const address = `0x${f.address.toString(16)}`;
      store.putNode({
        schema_version: 1,
        id: `fn_${f.address.toString(16)}`,
        kind: "function",
        binary,
        address,
        size: f.size,
        code: f.code,
      });
    }
    const input = { path: join(dir, "p") };
    expect(await checkReconstruction(store, binary, input)).toBeUndefined();

    await recordBehaviour(store, input.path, { argv: [] });
    await recordBehaviour(store, input.path, { argv: ["20"] });
    const check = await checkReconstruction(store, binary, input);
    expect(check).toMatchObject({ recorded: 2, reproduced: 2, failed: [] });
    expect(
      store
        .hypothesesFor(binary, "behaviour")
        .every((h) => h.confidence === "verified" && h.verification?.check === "replay"),
    ).toBe(true);
    store.close();
  }, 600_000);
});
