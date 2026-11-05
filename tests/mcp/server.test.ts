import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { GraphStore, repositoryPath } from "../../src/graph/index.js";
import { loadAnalysis } from "../../src/orchestrator/load-binary.js";

// The built server (npm test builds first), reached the way an AI client reaches it: over stdio, by the SDK's client.
const graph = join(mkdtempSync(join(tmpdir(), "atlas-mcp-")), "graph.sqlite");
const sha256 = "3".repeat(64);
let client: Client;

const call = async (
  name: string,
  args: Record<string, unknown>,
): Promise<{ isError?: boolean | undefined; body: unknown }> => {
  const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: { text: string }[] };
  return { isError: r.isError, body: JSON.parse(r.content[0]?.text ?? "null") };
};

beforeAll(async () => {
  const store = new GraphStore(graph);
  loadAnalysis(store, "target", {
    tool: { name: "test", version: "1" },
    sha256,
    functions: [
      { address: "0x1000", size: 8, label: "FUN_1000", thunk: false },
      { address: "0x2000", size: 8, label: "FUN_2000", thunk: false },
    ],
    calls: [{ from: "0x1000", to: "0x2000" }],
    strings: [],
    limitations: [],
  });
  store.close();
  client = new Client({ name: "atlas-test", version: "1" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [
        "--disable-warning=ExperimentalWarning",
        repositoryPath("dist", "src", "mcp", "server.js"),
        "--graph",
        graph,
      ],
    }),
  );
});

afterAll(async () => {
  await client.close();
});

describe("MCP server", () => {
  it("offers the CLI's operations as tools", async () => {
    const names = (await client.listTools()).tools.map((t) => t.name);
    for (const expected of [
      "run",
      "load",
      "get_function",
      "list_callers",
      "get_task_rewrite",
      "propose_rewrite",
      "verify",
    ]) {
      expect(names).toContain(expected);
    }
  });

  it("answers with the graph's data", async () => {
    const { body } = await call("get_function", { function: "0x1000" });
    expect(body).toMatchObject({ function: { address: "0x1000" }, callees: [{ address: "0x2000" }] });
    const named = await call("propose_name", { function: "0x2000", name: "helper" });
    expect(named.body).toMatchObject({ hypothesis: { kind: "name", value: "helper", confidence: "guessed" } });
  });

  it("reports errors as error results, with a message", async () => {
    const { isError, body } = await call("get_function", { function: "0x9999" });
    expect(isError).toBe(true);
    expect(body).toMatchObject({ error: { message: "no function at 0x9999" } });
  });
});
