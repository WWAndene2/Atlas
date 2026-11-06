import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { buildNotes } from "../../src/orchestrator/detect-toolchain.js";
import { binaryId, loadAnalysis } from "../../src/orchestrator/load-binary.js";

describe("buildNotes", () => {
  it("tells agents a binary is fortified from its calls to checked library functions", () => {
    const store = new GraphStore(":memory:");
    const sha = "1".repeat(64);
    loadAnalysis(store, "t", {
      tool: { name: "test", version: "1" },
      sha256: sha,
      functions: [
        { address: "0x10", size: 6, label: "__memcpy_chk", thunk: true },
        { address: "0x20", size: 6, label: "puts", thunk: true },
      ],
      calls: [],
      strings: [],
      limitations: [],
    });
    expect(buildNotes(store, binaryId(sha))).toEqual([expect.stringContaining("_FORTIFY_SOURCE")]);
    expect(buildNotes(store, binaryId(sha))[0]).toContain("__memcpy_chk");
    store.close();
  });
});
