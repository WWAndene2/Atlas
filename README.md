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

Status: in development, with these parts working and measured on Lua (built from its sources, as ground truth):

- **Analysis:** loading ELF, PE, 3DS titles and raw images with Ghidra and Rizin; names, types, systems and
  file formats as hypotheses; knowledge carried over from a documented build.
- **Rewriting:** C rewrites of functions checked byte for byte against the original, worked in parallel by agents.
- **Recompilation:** every function translated to C (`atlas lift`) and linked into a program for an x86-64 Linux
  host, from Linux, Windows, 32-bit ARM and AArch64 (Android, JNI) programs (`atlas lift --link`).
- **Behaviour:** a program's runs recorded as acceptance tests and replayed on its reconstruction, with coverage,
  differential fuzzing and blame (`atlas record`, `verify`, `coverage`, `fuzz`, `blame behaviour`).

Not there yet: a console's operating system and graphics (the current console path serves Linux system calls
only), and comparing what a program shows (images) rather than its text output. What exists:
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); what comes next: [`docs/ROADMAP.md`](docs/ROADMAP.md).

Development: Node.js 22.13 or later, then `npm ci` and `npm run check` (types, lint, format, tests).

Use Atlas only on software you own or are authorised to analyse.
