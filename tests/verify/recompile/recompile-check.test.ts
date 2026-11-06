import { describe, expect, it } from "vitest";
import { recompileCheck } from "../../../src/verify/recompile/recompile-check.js";
import { compiledBytes } from "./compile-helper.js";

const toolchain = { cc: "gcc", flags: ["-O2"] };
const source = "int scale(int x) { return x * 7 + 3; }\n";
const original = compiledBytes(source, "scale");

describe("recompileCheck", () => {
  it("passes a source that compiles to the original bytes", async () => {
    const r = await recompileCheck({ source, name: "scale", original, minimumSize: original.length, toolchain });
    expect(r).toMatchObject({ result: "pass", size: original.length });
  });

  it("passes when the original is followed by padding up to the next function", async () => {
    const padded = new Uint8Array([...original, 0x90, 0x90, 0x90]);
    const r = await recompileCheck({
      source,
      name: "scale",
      original: padded,
      minimumSize: original.length,
      toolchain,
    });
    expect(r.result).toBe("pass");
  });

  it("fails a source that computes something else, naming where", async () => {
    const r = await recompileCheck({
      source: "int scale(int x) { return x * 7 + 4; }\n",
      name: "scale",
      original,
      minimumSize: original.length,
      toolchain,
    });
    expect(r).toMatchObject({ result: "fail", reason: "mismatch" });
  });

  it("ignores the bytes a relocation fills: call targets are only known at link time", async () => {
    const caller = "extern int g(int);\nint f(int x) { return g(x) + 1; }\n";
    const bytes = compiledBytes(caller, "f");
    // In a linked binary the call's displacement holds a real offset; any value must be accepted.
    const linked = new Uint8Array(bytes);
    const call = linked.indexOf(0xe8);
    expect(call).toBeGreaterThanOrEqual(0);
    linked.set([0x12, 0x34, 0x56, 0x78], call + 1);
    const r = await recompileCheck({
      source: caller,
      name: "f",
      original: linked,
      minimumSize: linked.length,
      toolchain,
    });
    expect(r).toMatchObject({ result: "pass" });
    if (r.result === "pass") expect(r.masked).toBeGreaterThanOrEqual(4);
  });

  it("reports C that does not compile, with the compiler's message", async () => {
    const r = await recompileCheck({
      source: "int scale(int x) { return y; }\n",
      name: "scale",
      original,
      minimumSize: 1,
      toolchain,
    });
    expect(r).toMatchObject({ result: "fail", reason: "compile_error", details: expect.stringContaining("'y'") });
  });

  it("fails a candidate shorter than the engine's view of the function", async () => {
    const r = await recompileCheck({ source, name: "scale", original, minimumSize: original.length + 8, toolchain });
    expect(r.result).toBe("fail");
  });

  it("compares a function's body, not the cold part GCC splits off it", async () => {
    // GCC places the path to a cold call in .text.unlikely.sum (sum.cold), before .text.sum in the object. Taking
    // that section made two correct rewrites of Lua functions fail.
    const coldSource = [
      "__attribute__((cold, noreturn)) void fatal(const char *, int);",
      "extern int table[64];",
      "int sum(int *p, int n) {",
      "  int s = 0;",
      "  for (int i = 0; i < n; i++) {",
      '    if (p[i] < 0) fatal("negative", i);',
      "    s += table[p[i] & 63] * p[i];",
      "  }",
      "  return s;",
      "}",
      "",
    ].join("\n");
    const body = compiledBytes(coldSource, "sum");
    const r = await recompileCheck({
      source: coldSource,
      name: "sum",
      original: body,
      minimumSize: body.length,
      toolchain,
    });
    expect(r).toMatchObject({ result: "pass", size: body.length });
  });
});

describe("recompileCheck with the original's address", () => {
  // A global read by address, as Ghidra's C names it: the relocation's bytes are masked from the comparison, so
  // only the address check tells the right global from another.
  const global = "extern double DAT_00002000;\ndouble get(void) { return DAT_00002000; }";
  const compiled = compiledBytes(global, "get");
  // movsd disp32(%rip) (f2 0f 10 05), after an endbr64 where the compiler adds one: the field follows the opcode,
  // relative to the end of the 8-byte instruction.
  const start = compiled.findIndex(
    (_, i) => compiled[i] === 0xf2 && compiled[i + 1] === 0x0f && compiled[i + 3] === 0x05,
  );
  const at = (target: number) => {
    const bytes = new Uint8Array(compiled);
    new DataView(bytes.buffer).setInt32(start + 4, target - (0x1000 + start + 8), true);
    return bytes;
  };
  const check = (original: Uint8Array) =>
    recompileCheck({ source: global, name: "get", original, minimumSize: original.length, toolchain, address: 0x1000 });

  it("passes when the rewrite reads the global the original reads", async () => {
    expect((await check(at(0x2000))).result).toBe("pass");
  });
  it("fails when it reads another one", async () => {
    expect(await check(at(0x2010))).toMatchObject({ result: "fail", reason: "mismatch" });
  });
});
