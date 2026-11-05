import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { GraphStore } from "../../src/graph/index.js";
import { binaryId, functionId, loadAnalysis } from "../../src/orchestrator/load-binary.js";
import { proposeName } from "../../src/orchestrator/propose-name.js";
import { scoreNames } from "../../src/orchestrator/score-names.js";
import { functionSymbols } from "../../src/tools/symbols/index.js";

const key = fileURLToPath(new URL("../fixtures/lua/build/lua.symbols", import.meta.url));

describe("scoreNames", () => {
  it("can run, or the run does not require it", () => {
    expect(existsSync(key) || process.env.ATLAS_REQUIRE_FIXTURES !== "1").toBe(true);
  });

  // The graph is built from the key's own addresses (no engine needed): two functions labelled as a stripped binary
  // would have them, one exported (its label is its name), one anonymous.
  it.runIf(existsSync(key))("scores names against the real Lua key, free answers apart", async () => {
    const symbols = await functionSymbols(key);
    const named = symbols.find((s) => s.name === "luaL_checkinteger");
    const anonymous = symbols.find((s) => s.name === "luaH_getshortstr");
    expect(named && anonymous).toBeTruthy();
    const store = new GraphStore(":memory:");
    const sha256 = "5".repeat(64);
    loadAnalysis(store, "lua", {
      tool: { name: "test", version: "1" },
      sha256,
      functions: [
        { address: named?.address ?? "", size: 8, label: "luaL_checkinteger", thunk: false },
        { address: anonymous?.address ?? "", size: 8, label: "FUN_x", thunk: false },
      ],
      calls: [],
      strings: [],
      limitations: [],
    });
    proposeName(store, functionId(sha256, anonymous?.address ?? ""), "luaH_getshortstr", "agent");
    const score = await scoreNames(store, binaryId(sha256), key);
    expect(score).toMatchObject({ keyed: 2, free: 1, proposed: 1, verified: 1, accuracy: 1 });
    store.close();
  });
});
