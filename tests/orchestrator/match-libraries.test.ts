import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { binaryId, functionId, loadAnalysis } from "../../src/orchestrator/load-binary.js";
import { matchLibraries } from "../../src/orchestrator/match-libraries.js";
import { rewriteQueue } from "../../src/orchestrator/rewrite-queue.js";
import { compiledBytes } from "../verify/recompile/compile-helper.js";

// A library with one function calling another (a relocation inside it), built into an archive; the "binary" holds
// that function's bytes with the call resolved to some address, as a linker would leave it.
const source = "extern int helper(int);\nint lib_scale(int x) { return helper(x * 3) + helper(x + 7) + 11; }\n";

describe("matchLibraries", () => {
  it("recognises a library function behind resolved relocations, names it, and takes it out of the queue", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-match-"));
    writeFileSync(join(dir, "lib.c"), source);
    execFileSync("gcc", ["-O2", "-c", join(dir, "lib.c"), "-o", join(dir, "lib.o")]);
    execFileSync("ar", ["rcs", join(dir, "libtest.a"), join(dir, "lib.o")]);
    const linked = new Uint8Array(compiledBytes(source, "lib_scale"));
    for (let i = 0; i < linked.length; i++) if (linked[i] === 0xe8) linked.set([0x10, 0x20, 0x30, 0x00], i + 1);

    const store = new GraphStore(":memory:");
    const sha256 = "4".repeat(64);
    loadAnalysis(store, "game", {
      tool: { name: "test", version: "1" },
      sha256,
      functions: [
        {
          address: "0x1000",
          size: linked.length,
          label: "FUN_1000",
          thunk: false,
          code: Buffer.from(linked).toString("hex"),
        },
        { address: "0x2000", size: 16, label: "FUN_2000", thunk: false, code: "55".repeat(16) },
      ],
      calls: [],
      strings: [],
      limitations: [],
    });
    const outcome = await matchLibraries(store, binaryId(sha256), [join(dir, "libtest.a")]);
    expect(outcome).toMatchObject({ matched: 1, named: 1 });
    const fn = functionId(sha256, "0x1000");
    expect(store.hypothesesFor(fn, "match")[0]?.value).toMatchObject({ library: "libtest.a", names: ["lib_scale"] });
    expect(store.hypothesesFor(fn, "name")[0]?.value).toBe("lib_scale");
    expect(rewriteQueue(store, binaryId(sha256)).map((q) => q.id)).toEqual([functionId(sha256, "0x2000")]);
    store.close();
  });
});
