import { describe, expect, it } from "vitest";
import { TaskClaims } from "../../src/graph/index.js";

describe("TaskClaims", () => {
  it("gives each agent a different task, in order, until the lease ends", () => {
    const claims = new TaskClaims(":memory:");
    const now = 1_000_000;
    expect(claims.claimFirst(["a", "b", "c"], "agent-1", 60_000, now)?.task).toBe("a");
    expect(claims.claimFirst(["a", "b", "c"], "agent-2", 60_000, now)?.task).toBe("b");
    // After the first lease lapses, its task is free again.
    expect(claims.claimFirst(["a", "b", "c"], "agent-3", 60_000, now + 61_000)?.task).toBe("a");
    expect(claims.active(now + 61_000).map((c) => c.agent)).toEqual(["agent-3"]);
    claims.close();
  });

  it("lets only the holder release, and has nothing left once all are held", () => {
    const claims = new TaskClaims(":memory:");
    claims.claimFirst(["a"], "agent-1", 60_000);
    expect(claims.claimFirst(["a"], "agent-2", 60_000)).toBeUndefined();
    expect(claims.release("a", "agent-2")).toBe(false);
    expect(claims.release("a", "agent-1")).toBe(true);
    expect(claims.claimFirst(["a"], "agent-2", 60_000)?.agent).toBe("agent-2");
    claims.close();
  });

  it("puts a released task behind every task not yet tried", () => {
    const claims = new TaskClaims(":memory:");
    claims.claimFirst(["stuck", "b", "c"], "agent-1", 60_000);
    claims.release("stuck", "agent-1");
    expect(claims.claimFirst(["stuck", "b", "c"], "agent-1", 60_000)?.task).toBe("b");
    expect(claims.claimFirst(["stuck", "b", "c"], "agent-2", 60_000)?.task).toBe("c");
    expect(claims.claimFirst(["stuck", "b", "c"], "agent-3", 60_000)?.task).toBe("stuck");
    claims.close();
  });

  it("keeps the notes of agents that gave a task back, and gives only released tasks to an agent that asks", () => {
    const claims = new TaskClaims(":memory:");
    claims.claimFirst(["hard", "easy"], "small-model", 60_000);
    claims.release("hard", "small-model", "struct offsets right; 1 byte differs at a test operand order");
    // An agent for hard cases skips "easy", never released, and gets "hard".
    expect(
      claims.claimFirst(["hard", "easy"], "strong-model", 60_000, Date.now(), (_task, releases) => releases > 0)?.task,
    ).toBe("hard");
    expect(
      claims.claimFirst(["hard", "easy"], "strong-model-2", 60_000, Date.now(), (_task, releases) => releases > 0),
    ).toBeUndefined();
    expect(claims.notes("hard")).toEqual([
      { agent: "small-model", note: "struct offsets right; 1 byte differs at a test operand order" },
    ]);
    claims.close();
  });
});
