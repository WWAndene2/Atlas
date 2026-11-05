import { describe, expect, it } from "vitest";
import { mutationsFor } from "../../src/orchestrator/rewrite-mutations.js";

const SOURCE = `void lua_error(long L);
undefined8 helper(undefined8 a);
int f(undefined8 x, int y)
{
  if (x == y) lua_error(x);
  return helper(x) != 0;
}
`;

const apply = (label: string) =>
  mutationsFor(SOURCE, "f")
    .find((m) => m.label === label)
    ?.apply(SOURCE);

describe("mutationsFor", () => {
  it("offers static, attributes, noreturn per callee, type swaps and operand swaps", () => {
    const labels = mutationsFor(SOURCE, "f").map((m) => m.label);
    expect(labels).toContain("static on f, or not");
    expect(labels).toContain("__attribute__((noipa)) on f");
    expect(labels).toContain("noreturn on lua_error, or not");
    expect(labels).toContain("noreturn on helper, or not");
    expect(labels).toContain("undefined8 written long");
    expect(labels).toContain("operands of comparison 1 swapped");
  });
  it("edits only what each label says", () => {
    expect(apply("static on f, or not")).toContain("static int f(undefined8 x, int y)");
    expect(apply("__attribute__((cold)) on f")).toContain("__attribute__((cold)) int f(");
    expect(apply("noreturn on lua_error, or not")).toContain("__attribute__((noreturn)) void lua_error(long L);");
    expect(apply("undefined8 written long")).toContain("long helper(long a);");
    expect(apply("operands of comparison 1 swapped")).toContain("if (y == x)");
  });
});
