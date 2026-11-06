import { describe, expect, it } from "vitest";
import { assertHypothesis, SchemaError, type Hypothesis } from "../../src/graph/index.js";

// A behaviour (atlas record behaviour): a scenario and its outcome, on a binary, with a capture evidence.
const behaviour: Hypothesis = {
  schema_version: 1,
  id: "hyp_0123456789abcdef0123",
  node: "bin_0123456789abcdef",
  kind: "behaviour",
  value: {
    scenario: { argv: ["x"] },
    expected: { stdout: { text: "ok\n" }, stderr: { text: "" }, exit: 0, files: {} },
  },
  confidence: "observed",
  evidence: ["evd_0123456789abcdef"],
  author: { agent: "recorder" },
};

describe("hypothesis schema", () => {
  it("accepts a behaviour, and one the replay check verified", () => {
    expect(() => assertHypothesis(behaviour)).not.toThrow();
    expect(() =>
      assertHypothesis({
        ...behaviour,
        confidence: "verified",
        verification: { check: "replay", result: "pass", details: "reconstruction sha256 ..." },
      }),
    ).not.toThrow();
  });

  it("still refuses a kind or a check the schema does not name", () => {
    expect(() => assertHypothesis({ ...behaviour, kind: "scenario" as Hypothesis["kind"] })).toThrow(SchemaError);
    expect(() =>
      assertHypothesis({
        ...behaviour,
        verification: {
          check: "rerun" as NonNullable<Hypothesis["verification"]>["check"],
          result: "pass",
        },
      }),
    ).toThrow(SchemaError);
  });
});
