import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { GraphStore, TaskClaims } from "../../src/graph/index.js";
import { binaryId, functionId, loadAnalysis } from "../../src/orchestrator/load-binary.js";
import { releaseTask, unknownRewriteId } from "../../src/orchestrator/release-task.js";
import { rewriteQueue } from "../../src/orchestrator/rewrite-queue.js";
import { parseLevels } from "../../src/orchestrator/task-levels.js";

const sha256 = "a".repeat(64);
const small = functionId(sha256, "0x1000"); // 50 bytes: level 0 of 3
const large = functionId(sha256, "0x2000"); // 900 bytes: level 2 of 3, the top
const levels = parseLevels("3", "160,400");

let store: GraphStore;
let claims: TaskClaims;
beforeEach(() => {
  store = new GraphStore(":memory:");
  claims = new TaskClaims(":memory:");
  loadAnalysis(store, "target", {
    tool: { name: "test", version: "1" },
    sha256,
    functions: [
      { address: "0x1000", size: 50, label: "small", thunk: false, code: "90".repeat(50) },
      { address: "0x2000", size: 900, label: "large", thunk: false, code: "90".repeat(900) },
    ],
    calls: [],
    strings: [],
    limitations: [],
  });
});
afterEach(() => {
  store.close();
  claims.close();
});

describe("releaseTask", () => {
  it("closes a task as an unknown once the budget of top-level agents gave it up", () => {
    claims.claimFirst([large], "opus-1", 60_000);
    expect(releaseTask(store, claims, { task: large, agent: "opus-1", note: "block layout differs", levels })).toEqual({
      released: true,
      topReleases: 1,
    });
    expect(rewriteQueue(store, binaryId(sha256)).map((q) => q.id)).toContain(large);

    claims.claimFirst([large], "opus-2", 60_000);
    const outcome = releaseTask(store, claims, { task: large, agent: "opus-2", levels });
    expect(outcome).toEqual({ released: true, topReleases: 2, unknown: unknownRewriteId(large) });
    expect(store.getNode(unknownRewriteId(large))).toMatchObject({ kind: "unknown", address: "0x2000" });
    expect(rewriteQueue(store, binaryId(sha256)).map((q) => q.id)).toEqual([small]);
    expect(claims.notes(large)).toEqual([{ agent: "opus-1", note: "block layout differs" }]);
  });

  it("does not count a release below the top level: the task moves up instead", () => {
    claims.claimFirst([small], "haiku-1", 60_000);
    expect(releaseTask(store, claims, { task: small, agent: "haiku-1", levels, budget: 1 })).toEqual({
      released: true,
    });
    expect(store.getNode(unknownRewriteId(small))).toBeUndefined();
  });

  it("treats every agent as top level when there are no levels", () => {
    claims.claimFirst([small], "opus", 60_000);
    expect(releaseTask(store, claims, { task: small, agent: "opus", budget: 1 }).unknown).toBe(unknownRewriteId(small));
  });
});
