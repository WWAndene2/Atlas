import { describe, expect, it } from "vitest";
import type { GraphNode } from "../../src/graph/index.js";
import { segment } from "../../src/orchestrator/cluster-systems.js";

const fn = (i: number): GraphNode => ({
  schema_version: 1,
  id: `fn_${i}`,
  kind: "function",
  address: `0x${(i * 16).toString(16)}`,
});

describe("segment", () => {
  it("cuts functions in address order where calls stop crossing", () => {
    // Three modules of five functions; each calls within its module, one call goes from module 1 to module 2.
    const functions = Array.from({ length: 15 }, (_, i) => fn(i));
    const calls: Record<string, string[]> = {};
    for (let m = 0; m < 3; m++) {
      for (let k = 0; k < 5; k++) {
        const i = m * 5 + k;
        calls[`fn_${i}`] = [0, 1, 2, 3, 4].filter((j) => j !== k).map((j) => `fn_${m * 5 + j}`);
      }
    }
    calls.fn_4?.push("fn_7");
    expect(segment(functions, (f) => calls[f.id] ?? [])).toEqual([
      [0, 5],
      [5, 10],
      [10, 15],
    ]);
  });
  it("keeps a binary without calls in one run", () => {
    expect(segment([fn(0), fn(1)], () => [])).toHaveLength(1);
  });
});
