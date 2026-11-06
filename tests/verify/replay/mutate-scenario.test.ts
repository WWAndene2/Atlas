import { describe, expect, it } from "vitest";
import { generator, mutateScenario } from "../../../src/verify/replay/mutate-scenario.js";

describe("mutateScenario", () => {
  it("mutates the inputs the same way for the same seed, and keeps arguments and outputs", () => {
    const scenario = {
      argv: ["a"],
      stdin: "print(1 + 2)\n",
      inputs: [{ name: "in.txt", content: { text: "hello world" } }],
      outputs: ["out"],
    };
    const first = Array.from(
      { length: 20 },
      (
        (r) => () =>
          mutateScenario(scenario, r)
      )(generator(7)),
    );
    const again = Array.from(
      { length: 20 },
      (
        (r) => () =>
          mutateScenario(scenario, r)
      )(generator(7)),
    );
    expect(first).toEqual(again);
    expect(first.some((m) => m?.stdin !== scenario.stdin)).toBe(true);
    expect(first.some((m) => JSON.stringify(m?.inputs) !== JSON.stringify(scenario.inputs))).toBe(true);
    expect(first.every((m) => m?.argv === scenario.argv && m.outputs === scenario.outputs)).toBe(true);
  });

  it("has nothing to mutate without a standard input or an input file", () => {
    expect(mutateScenario({ argv: ["x"] }, generator(1))).toBeUndefined();
  });
});
