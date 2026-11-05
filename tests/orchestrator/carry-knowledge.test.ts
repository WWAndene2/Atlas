import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { carryKnowledge } from "../../src/orchestrator/carry-knowledge.js";

const SOURCES: Record<string, string> = {
  checksum:
    "unsigned checksum(const unsigned char*p,int n){unsigned s=0;for(int i=0;i<n;i++)s=(s<<5)+s+p[i];return s;}",
  clamp_all:
    "void clamp_all(int*v,int n,int lo,int hi){for(int i=0;i<n;i++){if(v[i]<lo)v[i]=lo;else if(v[i]>hi)v[i]=hi;}}",
  find_max: "long find_max(const long*v,int n){long m=v[0];for(int i=1;i<n;i++)if(v[i]>m)m=v[i];return m;}",
};

/** Machine code of each function, built with the flags given. */
function build(flags: string[]): Record<string, Buffer> {
  const dir = mkdtempSync(join(tmpdir(), "atlas-carry-"));
  writeFileSync(join(dir, "f.c"), Object.values(SOURCES).join("\n"));
  execFileSync("gcc", [...flags, "-fcf-protection=none", "-ffunction-sections", "-c", "f.c", "-o", "f.o"], {
    cwd: dir,
  });
  return Object.fromEntries(
    Object.keys(SOURCES).map((name) => {
      execFileSync("objcopy", ["-O", "binary", `--only-section=.text.${name}`, "f.o", `${name}.bin`], { cwd: dir });
      return [name, readFileSync(join(dir, `${name}.bin`))];
    }),
  );
}

/** A graph of one x86-64 binary with the functions in the given order, labelled as given. */
function graph(
  code: Record<string, Buffer>,
  order: string[],
  label: (name: string, address: number) => string,
): GraphStore {
  const store = new GraphStore(join(mkdtempSync(join(tmpdir(), "atlas-carry-g-")), "g.sqlite"));
  const bin = `bin_${order.join("").length.toString(16).padStart(16, "0")}`;
  store.putNode({ schema_version: 1, id: bin, kind: "binary", architecture: "x86_64" });
  let address = 0x1000;
  for (const name of order) {
    const bytes = code[name] as Buffer;
    store.putNode({
      schema_version: 1,
      id: `fn_${bin.slice(4)}_${address.toString(16)}`,
      kind: "function",
      binary: bin,
      address: `0x${address.toString(16)}`,
      size: bytes.length,
      code: bytes.toString("hex"),
      label: label(name, address),
    });
    address += 0x100;
  }
  return store;
}

describe("carryKnowledge", () => {
  it("names a stripped build's functions from a documented build with other flags, and brings verified rewrites", async () => {
    const documented = graph(build(["-O2"]), Object.keys(SOURCES), (name) => name);
    const doc = (name: string) => documented.nodesOfKind("function").find((f) => f.label === name)?.id as string;
    const rewrite = {
      schema_version: 1 as const,
      id: "hyp_00000000000000000000000000000001",
      node: doc("find_max"),
      kind: "rewrite" as const,
      value: { language: "c", source: SOURCES.find_max, name: "find_max" },
      confidence: "inferred" as const,
      evidence: [doc("find_max")],
      author: { agent: "test" },
    };
    documented.proposeHypothesis(rewrite);
    documented.recordVerification(rewrite.id, {
      confidence: "verified",
      verification: { check: "recompile", result: "pass", details: "test" },
    });
    // The target: another build (-O2 with -fno-tree-vectorize), stripped, functions in another order.
    const order = ["find_max", "clamp_all", "checksum"];
    const target = graph(
      build(["-O2", "-fno-tree-vectorize"]),
      order,
      (_, a) => `FUN_${a.toString(16).padStart(8, "0")}`,
    );
    const bin = target.nodesOfKind("binary")[0]?.id as string;
    const outcome = await carryKnowledge(target, bin, documented, documented.nodesOfKind("binary")[0]?.id as string);
    expect(outcome).toMatchObject({ compared: 3, matched: 3, names: 3, rewrites: 1 });
    for (const f of target.nodesOfKind("function")) {
      const expected = order[(Number(BigInt(f.address as string)) - 0x1000) / 0x100];
      expect(target.hypothesesFor(f.id, "name")[0]?.value).toBe(expected);
    }
    const carried = target.nodesOfKind("function").find((f) => f.address === "0x1000")?.id as string;
    expect(target.hypothesesFor(carried, "rewrite")[0]?.value).toMatchObject({ name: "find_max" });
  }, 60_000);
});
