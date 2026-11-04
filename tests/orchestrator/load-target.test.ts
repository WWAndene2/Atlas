import { mkdtempSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import type { Engine } from "../../src/orchestrator/engines.js";
import { NoEngineError, loadTarget } from "../../src/orchestrator/load-target.js";

const file = join(mkdtempSync(join(tmpdir(), "atlas-target-")), "target.bin");
writeFileSync(file, "not really a binary");
const sha256 = createHash("sha256").update("not really a binary").digest("hex");

const working: Engine = {
  name: "good",
  prepare: () => async () => ({
    tool: { name: "good", version: "1" },
    sha256,
    functions: [{ address: "0x10", size: 4, label: "f", thunk: false }],
    calls: [],
    strings: [],
    limitations: [],
  }),
};
const missing: Engine = {
  name: "missing",
  prepare: () => {
    throw new Error("not installed; run scripts/setup.sh");
  },
};
const lying: Engine = {
  name: "lying",
  prepare: () => async () => ({ ...(await working.prepare()({ path: file })), sha256: "0".repeat(64) }),
};

let store: GraphStore;
beforeEach(() => (store = new GraphStore(":memory:")));
afterEach(() => store.close());

describe("loadTarget", () => {
  it("loads with the engines that run and reports the others", async () => {
    const outcomes = await loadTarget(store, { path: file }, [missing, working]);
    expect(outcomes[0]).toEqual({ engine: "missing", skipped: "not installed; run scripts/setup.sh" });
    expect(outcomes[1]?.loaded?.functions).toBe(1);
  });

  it("refuses an engine's result for another file", async () => {
    const outcomes = await loadTarget(store, { path: file }, [lying, working]);
    expect(outcomes[0]?.skipped).toMatch(/another SHA-256/);
    expect(store.nodesOfKind("binary")).toHaveLength(1);
  });

  it("fails, naming every reason, when no engine can run", async () => {
    await expect(loadTarget(store, { path: file }, [missing])).rejects.toThrow(NoEngineError);
  });
});
