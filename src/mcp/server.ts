#!/usr/bin/env -S node --disable-warning=ExperimentalWarning
// Atlas's MCP server: the second door (docs/ROADMAP.md, How an AI uses Atlas), for AIs that cannot run commands and
// for one graph shared by several. Served over stdio; the graph is --graph, else $ATLAS_GRAPH, else ./atlas.sqlite.
import { parseArgs } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { GraphStore } from "../graph/index.js";
import { tools } from "./tools.js";

const { values } = parseArgs({ options: { graph: { type: "string" } } });
const store = new GraphStore(values.graph ?? process.env.ATLAS_GRAPH ?? "atlas.sqlite");
const server = new McpServer({ name: "atlas", version: "0.0.0" });

for (const [name, tool] of Object.entries(tools(store))) {
  server.registerTool(name, { description: tool.description, inputSchema: tool.input }, (async (args: never) => {
    try {
      const result = await (tool.handler as (a: never) => Promise<unknown>)(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    } catch (error) {
      // Errors answer like the CLI's --json: one document, here flagged as an error result.
      const message = error instanceof Error ? error.message : String(error);
      return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ error: { message } }) }] };
    }
  }) as never);
}

await server.connect(new StdioServerTransport());
