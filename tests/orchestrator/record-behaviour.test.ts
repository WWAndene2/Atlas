import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { fileSha256 } from "../../src/orchestrator/file-hash.js";
import { binaryId } from "../../src/orchestrator/load-binary.js";
import {
  InvalidScenarioError,
  recordBehaviour,
  UnstableBehaviourError,
} from "../../src/orchestrator/record-behaviour.js";
import { replayBehaviour } from "../../src/orchestrator/replay-behaviour.js";

function build(dir: string, name: string, source: string): string {
  writeFileSync(join(dir, `${name}.c`), source);
  execFileSync("gcc", ["-O1", `${name}.c`, "-o", name], { cwd: dir });
  return join(dir, name);
}

const ORIGINAL = `#include <stdio.h>
int main(int argc, char **argv) { printf("sum %d\\n", argc * 10); return argc; }`;
// The same behaviour from a different program (a reconstruction), and one that differs on one scenario only.
const REBUILT = `#include <stdio.h>
int main(int c, char **v) { int s = 0; for (int i = 0; i < c; i++) s += 10; printf("sum %d\\n", s); return c; }`;
const WRONG = `#include <stdio.h>
int main(int argc, char **argv) { printf("sum %d\\n", argc == 3 ? 0 : argc * 10); return argc; }`;

async function loaded(store: GraphStore, program: string): Promise<string> {
  const id = binaryId(await fileSha256(program));
  store.putNode({ schema_version: 1, id, kind: "binary", architecture: "x86_64" });
  return id;
}

describe("recordBehaviour and replayBehaviour", () => {
  it("records observed scenarios, verifies a reconstruction that reproduces them, and says where one does not", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-behaviour-"));
    const store = new GraphStore(join(dir, "g.sqlite"));
    const original = build(dir, "original", ORIGINAL);
    const binary = await loaded(store, original);
    const one = await recordBehaviour(store, original, { argv: [] });
    const two = await recordBehaviour(store, original, { argv: ["a", "b"] });
    expect(one.created && two.created).toBe(true);
    expect(one.hypothesis).toMatchObject({ node: binary, kind: "behaviour", confidence: "observed" });
    expect((await recordBehaviour(store, original, { argv: [] })).created).toBe(false);
    expect(store.getEvidence(one.hypothesis.evidence[0] as string)?.source).toBe("capture");

    const good = await replayBehaviour(store, original, build(dir, "rebuilt", REBUILT));
    expect(good.results.map((r) => r.result)).toEqual(["pass", "pass"]);
    expect(store.getHypothesis(one.hypothesis.id)).toMatchObject({
      confidence: "verified",
      verification: { check: "replay", result: "pass" },
    });

    const bad = await replayBehaviour(store, original, build(dir, "wrong", WRONG));
    expect(bad.results.map((r) => r.result)).toEqual(["pass", "fail"]);
    expect(bad.results[1]?.differences).toEqual(["stdout: first difference at byte 4 (7 expected, 6 got)"]);
    expect(store.getHypothesis(two.hypothesis.id)).toMatchObject({
      confidence: "observed",
      verification: { check: "replay", result: "fail" },
    });
    store.close();
  }, 120_000);

  it("refuses a scenario the program does not repeat", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-behaviour-"));
    const store = new GraphStore(join(dir, "g.sqlite"));
    const clock = build(
      dir,
      "clock",
      `#include <stdio.h>\n#include <time.h>\nint main(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); printf("%ld\\n", t.tv_nsec); return 0; }`,
    );
    await loaded(store, clock);
    await expect(recordBehaviour(store, clock, { argv: [] })).rejects.toBeInstanceOf(UnstableBehaviourError);
    store.close();
  }, 60_000);

  it("records a scenario whose varying part is named, and replays it with that part masked", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-behaviour-"));
    const store = new GraphStore(join(dir, "g.sqlite"));
    const source = (word: string) =>
      `#include <stdio.h>\n#include <time.h>\nint main(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); printf("${word} %ld\\n", t.tv_nsec); return 0; }`;
    const clock = build(dir, "clock", source("now"));
    await loaded(store, clock);
    const { hypothesis } = await recordBehaviour(store, clock, { argv: [], vary: ["\\d+"] });
    expect(hypothesis.confidence).toBe("observed");
    const same = await replayBehaviour(store, clock, build(dir, "clock2", source("now")));
    expect(same.results.map((r) => r.result)).toEqual(["pass"]);
    const other = await replayBehaviour(store, clock, build(dir, "clock3", source("then")));
    expect(other.results.map((r) => r.result)).toEqual(["fail"]);
    await expect(recordBehaviour(store, clock, { argv: [], vary: ["("] })).rejects.toBeInstanceOf(InvalidScenarioError);
    store.close();
  }, 120_000);

  it("refuses a program that is not loaded", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-behaviour-"));
    const store = new GraphStore(join(dir, "g.sqlite"));
    await expect(recordBehaviour(store, build(dir, "p", ORIGINAL), { argv: [] })).rejects.toThrow(/not loaded/);
    store.close();
  }, 60_000);
});
