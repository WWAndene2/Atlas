# Atlas

Atlas is a reverse-engineering platform built for AI agents. It turns a binary (a program or a game) into a
shared, versioned **knowledge graph**: functions, types, systems, file formats, shaders. Each fact in the graph
carries its evidence and a confidence level. A **verification loop** checks every hypothesis an agent makes
(a rewritten function, a type, a name) against the original before the graph trusts it.

Atlas is not tied to one AI or one language:

- **Any agent** (Claude Code, Codex, Cursor, Gemini CLI, a script calling a model API) uses Atlas through its
  **MCP server** or its **CLI** (`--json`). Instructions for agents are in [`AGENTS.md`](AGENTS.md).
- **The graph is open data:** a SQLite database with a JSONL export, described by the JSON Schemas in
  [`schema/`](schema/). An agent can read it without running Atlas.
- **The analysis tools** (Ghidra, IDA, Rizin, JEB, Frida, file-format parsers) come through
  [REA](https://github.com/morluto/rea), used as Atlas's tools layer.

Status: design. The architecture is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); nothing runs yet.

Use Atlas only on software you own or are authorised to analyse.
