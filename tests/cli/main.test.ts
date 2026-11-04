import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { GraphStore, repositoryPath } from "../../src/graph/index.js";
import { loadAnalysis } from "../../src/orchestrator/load-binary.js";

// Runs the built CLI (npm test builds first) as an agent would, on a graph filled through the loader.
const cli = repositoryPath("dist", "src", "cli", "main.js");
const graph = join(mkdtempSync(join(tmpdir(), "atlas-cli-")), "graph.sqlite");
const sha256 = "e".repeat(64);

function atlas(...args: string[]): { code: number | null; out: unknown; stderr: string } {
  const r = spawnSync(
    process.execPath,
    ["--disable-warning=ExperimentalWarning", cli, ...args, "--graph", graph, "--json"],
    {
      encoding: "utf8",
      env: { ...process.env, GHIDRA_INSTALL_DIR: "" },
    },
  );
  return { code: r.status, out: r.stdout === "" ? undefined : JSON.parse(r.stdout), stderr: r.stderr };
}

beforeAll(() => {
  const store = new GraphStore(graph);
  loadAnalysis(store, "/x/target", {
    tool: { name: "test", version: "1" },
    sha256,
    functions: [
      { address: "0x1000", size: 16, label: "FUN_00001000", thunk: false },
      { address: "0x1010", size: 8, label: "FUN_00001010", thunk: false },
    ],
    calls: [{ from: "0x1000", to: "0x1010" }],
    strings: [{ address: "0x3000", value: "usage: %s", readers: ["0x1000"] }],
    limitations: [],
  });
  store.close();
});

describe("atlas CLI", () => {
  it("gets a function by address with its context", () => {
    const { code, out } = atlas("get", "function", "0x1000");
    expect(code).toBe(0);
    expect(out).toMatchObject({
      function: { address: "0x1000" },
      callees: [{ address: "0x1010" }],
      strings: [{ label: "usage: %s" }],
    });
  });

  it("lists callers by function ID", () => {
    const { code, out } = atlas("list", "callers", `fn_${sha256.slice(0, 16)}_1010`);
    expect(code).toBe(0);
    expect(out).toMatchObject({ callers: [{ address: "0x1000" }] });
  });

  it("exports the graph", () => {
    const { out } = atlas("export");
    expect((out as { jsonl: string }).jsonl.split("\n").filter(Boolean)).toHaveLength(7); // evidence, binary, 2 functions, string, call, read
  });

  it("answers errors in JSON with an exit code", () => {
    expect(atlas("get", "function", "0x9")).toMatchObject({ code: 1, out: { error: { code: "not_found" } } });
    expect(atlas("load", "/nonexistent")).toMatchObject({ code: 1, out: { error: { code: "not_found" } } });
    expect(atlas("frobnicate")).toMatchObject({ code: 2, out: { error: { code: "usage" } } });
  });

  it("reports why no engine could load a binary", () => {
    const { code, out } = atlas("load", cli);
    expect(code).toBe(1);
    expect(out).toMatchObject({ error: { code: "no_engine", message: expect.stringContaining("GHIDRA_INSTALL_DIR") } });
  });
});
