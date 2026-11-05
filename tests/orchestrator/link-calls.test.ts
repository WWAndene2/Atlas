import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { linkCalls } from "../../src/orchestrator/link-calls.js";
import { checkEquivalence, locateAngr, runDifferential } from "../../src/tools/angr/index.js";
import { functionSection, readObjectFile } from "../../src/verify/recompile/object-file.js";

const BIN = "bin_00000000000000bb";

function angr(): string | undefined {
  try {
    return locateAngr();
  } catch {
    return undefined;
  }
}
const python = angr();

function graph(): GraphStore {
  const store = new GraphStore(join(mkdtempSync(join(tmpdir(), "atlas-link-")), "g.sqlite"));
  store.putNode({ schema_version: 1, id: BIN, kind: "binary", architecture: "x86_64" });
  store.putNode({
    schema_version: 1,
    id: "fn_00000000000000bb_400800",
    kind: "function",
    binary: BIN,
    address: "0x400800",
    label: "g",
  });
  return store;
}

/** f compiled alone, its calls linked to the graph's g, placed at `address`. */
async function build(store: GraphStore, source: string, flags: string[], address: number) {
  const dir = mkdtempSync(join(tmpdir(), "atlas-link-cc-"));
  writeFileSync(join(dir, "f.c"), source);
  execFileSync("gcc", [...flags, "-fcf-protection=none", "-ffunction-sections", "-c", "f.c", "-o", "f.o"], {
    cwd: dir,
  });
  const section = functionSection(await readObjectFile(join(dir, "f.o")), "f");
  if (section === undefined) throw new Error("no f");
  return { ...linkCalls(store, BIN, section.bytes, section.relocations, address, source), address };
}

describe("linkCalls", () => {
  it("patches calls to the binary's callee and reads each callee's arity from its prototype", async () => {
    const store = graph();
    const linked = await build(store, "int g(int, long);\nint f(int x){return g(x, 2)+1;}", ["-O2"], 0x40000000);
    expect(linked.unresolved).toEqual([]);
    expect(linked.arity).toEqual({ "0x400800": 2 });
    const none = await build(store, "int h(int);\nint f(int x){return h(x);}", ["-O2"], 0x40000000);
    expect(none.unresolved).toEqual(["h"]);
  });
});

describe.runIf(python !== undefined)("behaviour checks across calls", () => {
  const compare = async (a: [string, string[]], b: [string, string[]]) => {
    const store = graph();
    const o = await build(store, ...a, 0x401000);
    const c = await build(store, ...b, 0x40000000);
    const versions = [
      { code: o.code, address: o.address },
      { code: c.code, address: c.address },
    ] as const;
    return {
      equivalence: await checkEquivalence(python as string, ...versions, { arity: { ...o.arity, ...c.arity } }),
      differential: await runDifferential(python as string, ...versions, {
        arity: { ...o.arity, ...c.arity },
        inputs: 10,
      }),
    };
  };
  it("proves two builds that make the same call equivalent", async () => {
    const f = "int g(int);\nint f(int x){return g(x*2)+1;}";
    const r = await compare([f, ["-O2"]], [f, ["-O0"]]);
    expect(r.equivalence.result).toBe("equivalent");
    expect(r.differential.result).toBe("same");
  }, 240_000);
  it("finds a call made with another argument", async () => {
    const r = await compare(
      ["int g(int);\nint f(int x){return g(x*2)+1;}", ["-O2"]],
      ["int g(int);\nint f(int x){return g(x*3)+1;}", ["-O2"]],
    );
    expect(r.equivalence.result).toBe("different");
    expect(r.differential.result).toBe("different");
  }, 240_000);
  it("stays inconclusive when the callee's arity is unknown", async () => {
    const f = "int g();\nint f(int x){return g(x*2)+1;}";
    expect((await compare([f, ["-O2"]], [f, ["-O0"]])).equivalence.result).toBe("inconclusive");
  }, 240_000);
});
