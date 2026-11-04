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
});
