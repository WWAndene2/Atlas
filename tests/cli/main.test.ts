import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { GraphStore, repositoryPath } from "../../src/graph/index.js";
import { loadAnalysis } from "../../src/orchestrator/load-binary.js";
import { compiledBytes } from "../verify/recompile/compile-helper.js";

// Runs the built CLI (npm test builds first) as an agent would, on a graph filled through the loader.
const cli = repositoryPath("dist", "src", "cli", "main.js");
const graph = join(mkdtempSync(join(tmpdir(), "atlas-cli-")), "graph.sqlite");
const sha256 = "e".repeat(64);
const scaleSource = "int scale(int x) { return x * 7 + 3; }\n";
const scaleCode = Buffer.from(compiledBytes(scaleSource, "scale")).toString("hex");

function atlas(...args: string[]): { code: number | null; out: unknown; stderr: string } {
  const r = spawnSync(
    process.execPath,
    ["--disable-warning=ExperimentalWarning", cli, ...args, "--graph", graph, "--json"],
    {
      encoding: "utf8",
      env: { ...process.env, GHIDRA_INSTALL_DIR: "", ATLAS_TOOLS_DIR: "/nonexistent" },
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
      { address: "0x2000", size: scaleCode.length / 2, label: "FUN_00002000", thunk: false, code: scaleCode },
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
    // evidence, binary, 3 functions, string, call, read
    expect((out as { jsonl: string }).jsonl.split("\n").filter(Boolean)).toHaveLength(8);
  });

  it("takes an agent's rewrite and verifies it by recompiling", () => {
    const file = join(dirname(graph), "scale.c");
    writeFileSync(file, scaleSource);
    const proposed = atlas("propose", "rewrite", "0x2000", "--source", file, "--name", "scale");
    expect(proposed).toMatchObject({ code: 0, out: { hypothesis: { kind: "rewrite", confidence: "guessed" } } });
    const id = (proposed.out as { hypothesis: { id: string } }).hypothesis.id;
    const verified = atlas("verify", id, "--cc", "gcc", "--cflags=-O2");
    expect(verified).toMatchObject({
      code: 0,
      out: { check: { result: "pass" }, hypothesis: { confidence: "verified" } },
    });
    expect(atlas("verify", "all", "--cc", "gcc", "--cflags=-O2")).toMatchObject({ out: { checked: 0 } });
    // Without --cc, the binary's detected toolchain is used; there is none here, and the error says how to get one.
    expect(atlas("verify", id)).toMatchObject({
      code: 2,
      out: { error: { message: expect.stringContaining("atlas detect toolchain") } },
    });
  });

  it("lists the functions to rewrite and gives an agent's task for one", () => {
    const list = atlas("list", "tasks", "rewrite");
    expect(list).toMatchObject({ code: 0, out: { open: expect.any(Number) } });
    const task = atlas("get", "task", "rewrite", "0x1000");
    expect(task).toMatchObject({ code: 0, out: { function: { address: "0x1000" }, status: "open" } });
    expect((task.out as { answer: string }).answer).toContain("atlas propose rewrite");
  });

  it("answers errors in JSON with an exit code", () => {
    expect(atlas("get", "function", "0x9")).toMatchObject({ code: 1, out: { error: { code: "not_found" } } });
    expect(atlas("load", "/nonexistent")).toMatchObject({ code: 1, out: { error: { code: "not_found" } } });
    expect(atlas("frobnicate")).toMatchObject({ code: 2, out: { error: { code: "usage" } } });
  });

  it("exits cleanly when its reader closes the pipe early", () => {
    // Output far larger than a pipe's buffer, so the CLI is still writing when head has gone.
    const big = join(mkdtempSync(join(tmpdir(), "atlas-cli-")), "big.sqlite");
    const store = new GraphStore(big);
    loadAnalysis(store, "/x/big", {
      tool: { name: "test", version: "1" },
      sha256: "f".repeat(64),
      functions: Array.from({ length: 5000 }, (_, i) => ({
        address: `0x${(0x1000 + i * 16).toString(16)}`,
        size: 16,
        label: `FUN_${i}`,
        thunk: false,
      })),
      calls: [],
      strings: [],
      limitations: [],
    });
    store.close();
    const r = spawnSync(
      "bash",
      ["-c", `node --disable-warning=ExperimentalWarning ${cli} list functions --json --graph ${big} | head -c 1`],
      { encoding: "utf8" },
    );
    expect(r.stderr).toBe("");
    expect(r.stdout).toBe("{");
  });

  it("checks the raw-image options before loading", () => {
    expect(atlas("load", cli, "--arch", "arm-v6k")).toMatchObject({ code: 2, out: { error: { code: "usage" } } });
    expect(atlas("load", cli, "--arch", "z80", "--base", "0x0")).toMatchObject({
      code: 2,
      out: { error: { message: expect.stringContaining("arm-v6k") } },
    });
    expect(atlas("load", cli, "--arch", "arm-v6k", "--base", "100000")).toMatchObject({ code: 2 });
  });

  it("reports why no engine could load a binary", () => {
    const { code, out } = atlas("load", cli);
    expect(code).toBe(1);
    expect(out).toMatchObject({ error: { code: "no_engine", message: expect.stringContaining("scripts/setup.sh") } });
  });
});
