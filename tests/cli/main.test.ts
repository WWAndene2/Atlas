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

  it("takes an agent's name for a function", () => {
    const named = atlas("propose", "name", "0x1000", "lua_main");
    expect(named).toMatchObject({
      code: 0,
      out: { hypothesis: { kind: "name", value: "lua_main", confidence: "guessed" } },
    });
    expect(atlas("propose", "name", "0x1000", "not a name")).toMatchObject({ code: 1 });
    expect(atlas("score", "names")).toMatchObject({ code: 2, out: { error: { code: "usage" } } });
  });

  it("asks for a goal before running the whole job", () => {
    expect(atlas("run", cli)).toMatchObject({
      code: 2,
      out: { error: { message: expect.stringContaining("--goal") } },
    });
  });

  it("hands agents claiming at the same moment different tasks", async () => {
    // Eight processes at once, as eight subagents would, on a graph of ten open functions: no task twice.
    const { spawn } = await import("node:child_process");
    const own = join(dirname(graph), "claims.sqlite");
    const store = new GraphStore(own);
    loadAnalysis(store, "target", {
      tool: { name: "test", version: "1" },
      sha256: "c".repeat(64),
      functions: Array.from({ length: 10 }, (_, i) => ({
        address: `0x${(0x1000 + i * 16).toString(16)}`,
        size: 8,
        label: `FUN_${i}`,
        thunk: false,
        code: "90".repeat(16),
      })),
      calls: [],
      strings: [],
      limitations: [],
    });
    store.close();
    const claimOnce = (agent: string): Promise<string> =>
      new Promise((resolve) => {
        const p = spawn(process.execPath, [
          "--disable-warning=ExperimentalWarning",
          cli,
          "claim",
          "task",
          "rewrite",
          "--agent",
          agent,
          "--graph",
          own,
          "--json",
        ]);
        let out = "";
        p.stdout.on("data", (d: Buffer) => (out += d.toString()));
        p.on("close", () => resolve(out));
      });
    const results = await Promise.all(Array.from({ length: 8 }, (_, i) => claimOnce(`agent-${i}`)));
    const tasks = results
      .map((r) => (JSON.parse(r) as { claim: { task: string } | null }).claim?.task)
      .filter((t) => t !== undefined);
    expect(tasks).toHaveLength(8);
    expect(new Set(tasks).size).toBe(8);
    const someone = tasks[0] as string;
    const holder = `agent-${results.findIndex((r) => r.includes(someone))}`;
    const release = spawnSync(
      process.execPath,
      [
        "--disable-warning=ExperimentalWarning",
        cli,
        "release",
        "task",
        someone,
        "--agent",
        holder,
        "--graph",
        own,
        "--json",
      ],
      { encoding: "utf8" },
    );
    expect(JSON.parse(release.stdout)).toEqual({ released: true });
    // A note left on release reaches the next agent, in claim and in get task; --released takes only that task.
    const noteRelease = spawnSync(
      process.execPath,
      [
        "--disable-warning=ExperimentalWarning",
        cli,
        "claim",
        "task",
        "rewrite",
        "--agent",
        "first",
        "--graph",
        own,
        "--json",
      ],
      { encoding: "utf8" },
    );
    const held = (JSON.parse(noteRelease.stdout) as { claim: { task: string } }).claim.task;
    spawnSync(
      process.execPath,
      [
        "--disable-warning=ExperimentalWarning",
        cli,
        "release",
        "task",
        held,
        "--agent",
        "first",
        "--note",
        "near miss at offset 8",
        "--graph",
        own,
      ],
      { encoding: "utf8" },
    );
    const strong = spawnSync(
      process.execPath,
      [
        "--disable-warning=ExperimentalWarning",
        cli,
        "claim",
        "task",
        "rewrite",
        "--agent",
        "strong",
        "--released",
        "--graph",
        own,
        "--json",
      ],
      { encoding: "utf8" },
    );
    const answer = JSON.parse(strong.stdout) as { claim: { task: string }; notes: { note: string }[] };
    expect([someone, held]).toContain(answer.claim.task);
    const task = spawnSync(
      process.execPath,
      ["--disable-warning=ExperimentalWarning", cli, "get", "task", "rewrite", held, "--graph", own, "--json"],
      { encoding: "utf8" },
    );
    expect((JSON.parse(task.stdout) as { notes: { note: string }[] }).notes).toEqual([
      { agent: "first", note: "near miss at offset 8" },
    ]);
  });

  it("routes claims by level: small to the first level, large to the last, given back one level up", () => {
    const routed = join(dirname(graph), "levels.sqlite");
    const store = new GraphStore(routed);
    loadAnalysis(store, "target", {
      tool: { name: "test", version: "1" },
      sha256: "d".repeat(64),
      functions: [
        { address: "0x1000", size: 50, label: "small", thunk: false, code: "90".repeat(50) },
        { address: "0x2000", size: 900, label: "large", thunk: false, code: "90".repeat(900) },
      ],
      calls: [],
      strings: [],
      limitations: [],
    });
    store.close();
    const run = (...args: string[]): { claim: { task: string } | null } =>
      JSON.parse(
        spawnSync(
          process.execPath,
          ["--disable-warning=ExperimentalWarning", cli, ...args, "--graph", routed, "--json"],
          {
            encoding: "utf8",
          },
        ).stdout,
      );
    const levels = ["--of", "3", "--bounds", "160,400"];
    const small = run("claim", "task", "rewrite", "--agent", "h", "--level", "0", ...levels).claim?.task ?? "";
    expect(small).toMatch(/_1000$/);
    expect(run("claim", "task", "rewrite", "--agent", "o", "--level", "2", ...levels).claim?.task).toMatch(/_2000$/);
    expect(run("claim", "task", "rewrite", "--agent", "s", "--level", "1", ...levels).claim).toBeNull();
    spawnSync(process.execPath, [
      "--disable-warning=ExperimentalWarning",
      cli,
      "release",
      "task",
      small,
      "--agent",
      "h",
      "--graph",
      routed,
    ]);
    expect(run("claim", "task", "rewrite", "--agent", "s", "--level", "1", ...levels).claim?.task).toBe(small);
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
