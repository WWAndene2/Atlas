import { describe, expect, it } from "vitest";
import { agentPlan } from "../../src/orchestrator/agent-plan.js";
import { parseLevels, taskLevel } from "../../src/orchestrator/task-levels.js";

describe("taskLevel", () => {
  const three = parseLevels("3", "160,400");

  it("sends small functions low, large ones high, and a given-back task one level up", () => {
    expect(taskLevel(100, 0, three)).toBe(0);
    expect(taskLevel(300, 0, three)).toBe(1);
    expect(taskLevel(900, 0, three)).toBe(2);
    expect(taskLevel(100, 1, three)).toBe(1); // Haiku gave it back: Sonnet's
    expect(taskLevel(100, 2, three)).toBe(2); // Sonnet too: Opus's
    expect(taskLevel(900, 4, three)).toBe(2); // no level above the top
  });

  it("refuses bounds that do not fit the levels", () => {
    expect(() => parseLevels("2", "160,400")).toThrow();
    expect(() => parseLevels("3", "400,160")).toThrow();
  });
});

describe("agentPlan", () => {
  it("gives each mode its models, every level at least one agent", () => {
    const models = (mode: "adaptive" | "high" | "medium" | "low") =>
      agentPlan(mode, 8, "g.sqlite").tiers.map((t) => [t.model, t.agents.length]);
    expect(models("adaptive")).toEqual([
      ["haiku", 4],
      ["sonnet", 2],
      ["opus", 2],
    ]);
    expect(models("high")).toEqual([["opus", 8]]);
    expect(models("medium")).toEqual([
      ["sonnet", 5],
      ["opus", 3],
    ]);
    expect(models("low")).toEqual([
      ["haiku", 6],
      ["opus", 2],
    ]);
    expect(agentPlan("low", 1, "g.sqlite").tiers.map((t) => t.agents.length)).toEqual([1, 1]);
  });

  it("writes claim commands that route by level", () => {
    const plan = agentPlan("adaptive", 3, "g.sqlite");
    expect(plan.tiers[0]?.claim).toBe(
      "atlas claim task rewrite --agent <agent> --level 0 --of 3 --bounds 160,400 --graph g.sqlite --json",
    );
    expect(agentPlan("high", 2, "g.sqlite").tiers[0]?.claim).toBe(
      "atlas claim task rewrite --agent <agent> --graph g.sqlite --json",
    );
  });
});
