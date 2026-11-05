import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { namedByClues, orderByClues } from "../../src/orchestrator/detect-toolchain.js";

// Uses the compilers installed by scripts/setup.sh; each case runs only where its compilers are.
const has = (cc: string): boolean => spawnSync(cc, ["--version"]).status === 0;

describe("compiler clues", () => {
  it.runIf(has("gcc-11") && has("gcc-12"))("name the GCC release the binary was built with", () => {
    const clue = ["GCC: (Ubuntu 11.5.0-1ubuntu1~24.04.1) 11.5.0"];
    expect(namedByClues({ cc: "gcc-11", flags: [] }, clue)).toBe(true);
    expect(namedByClues({ cc: "gcc-12", flags: [] }, clue)).toBe(false);
    const ordered = orderByClues(
      [
        { cc: "gcc-12", flags: [] },
        { cc: "gcc-11", flags: [] },
      ],
      clue,
    );
    expect(ordered.map((t) => t.cc)).toEqual(["gcc-11", "gcc-12"]);
  });

  it.runIf(has("clang-17") && has("gcc-11"))("tell Clang from GCC, and name nothing without clues", () => {
    expect(namedByClues({ cc: "clang-17", flags: [] }, ["clang version 17.0.6"])).toBe(true);
    expect(namedByClues({ cc: "gcc-11", flags: [] }, ["clang version 11.1.0"])).toBe(false);
    expect(namedByClues({ cc: "clang-17", flags: [] }, [])).toBe(false);
  });
});
