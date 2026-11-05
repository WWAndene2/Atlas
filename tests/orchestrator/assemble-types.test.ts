import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { assembleTypes } from "../../src/orchestrator/assemble-types.js";

const BIN = "bin_00000000000000aa";

function withFields(store: GraphStore, n: number, fields: [number, number][]): void {
  const id = `fn_00000000000000aa_${n}`;
  store.putNode({ schema_version: 1, id, kind: "function", binary: BIN, address: `0x${n.toString(16)}` });
  store.proposeHypothesis({
    schema_version: 1,
    id: `hyp_${n.toString(16).padStart(32, "0")}`,
    node: id,
    kind: "signature",
    value: {
      arguments: [{ register: "rdi", fields: fields.map(([offset, size]) => ({ offset, size, access: "r" })) }],
    },
    confidence: "inferred",
    evidence: [id],
    author: { agent: "typer/angr" },
  });
}

describe("assembleTypes", () => {
  it("gives arguments touching mostly the same fields one struct, and keeps a conflicting one apart", () => {
    const store = new GraphStore(join(mkdtempSync(join(tmpdir(), "atlas-types-")), "g.sqlite"));
    store.putNode({ schema_version: 1, id: BIN, kind: "binary", architecture: "x86_64" });
    withFields(store, 1, [
      [0, 8],
      [8, 8],
      [16, 4],
      [24, 8],
    ]);
    withFields(store, 2, [
      [8, 8],
      [16, 4],
      [32, 8],
    ]);
    withFields(store, 3, [
      [0, 8],
      [24, 8],
    ]);
    // Same offsets, other widths: another struct.
    withFields(store, 4, [
      [0, 4],
      [4, 4],
      [8, 2],
    ]);
    const o = assembleTypes(store, BIN);
    expect(o.types.map((t) => t.used_by)).toEqual([3, 1]);
    const layout = (store.hypothesesFor(o.types[0]?.id as string, "type")[0]?.value as { layout: { offset: number }[] })
      .layout;
    expect(layout.map((f) => f.offset)).toEqual([0, 8, 16, 24, 32]);
  });
});
