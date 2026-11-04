# Atlas roadmap

The order of development, what each milestone delivers and how it is judged done. Durations are estimates, not
measurements. Update this file when a milestone finishes or the plan changes.

## How an AI uses Atlas

Atlas calls no AI model itself until M6. The AI is whichever assistant the operator already uses (Claude, GPT,
Gemini...), and it reaches Atlas through one of two doors onto the same engine and graph:

1. **Clone and run (the main door).** The AI is given the repository's address, clones it into its own environment,
   runs `scripts/setup.sh`, then uses the CLI (`--json`), following `AGENTS.md`. For any AI that can run commands
   (Claude Code, Codex, Cursor's agent, Gemini CLI).
2. **MCP.** The AI connects to an Atlas already running somewhere. For AIs that cannot run commands (chat in a
   browser) and for one graph shared by several AIs or people.

Running many agents in parallel, with Atlas calling model APIs itself, comes at M6, once the method is measured.

## Principle: write the core, reuse the rest

Only three parts do not exist elsewhere and are written for Atlas: the **knowledge graph**, the **verification
loop** and the **orchestrator**. Everything else is reused, each dependency added at the milestone that needs it,
pinned, with its licence checked when added (AGENTS.md section 8).

| Need                                    | Project                               | Use in Atlas                                   | Milestone |
| --------------------------------------- | ------------------------------------- | ---------------------------------------------- | --------- |
| Analysis tools behind one MCP interface | [REA](https://github.com/morluto/rea) | Tools layer (`src/tools/rea/`)                 | M1        |
| Free decompiler                         | Ghidra, through REA                   | Default engine: no commercial licence required | M1        |
| Light disassembly                       | Rizin, through REA                    | Fast analysis, CI                              | M1        |
| MCP server                              | Official MCP TypeScript SDK           | Second door (`src/mcp/`)                       | M2        |
| Graph storage                           | SQLite (`node:sqlite`)                | `src/graph/`                                   | M0        |
| Schema validation                       | Ajv                                   | Records checked against `schema/`              | M0        |
| Code comparison                         | objdiff                               | Rewrite checker                                | M3        |
| Equivalence of small functions          | Z3, angr                              | Structural checker                             | M3        |
| Execution traces                        | Frida                                 | Dynamic data                                   | M4        |
| File formats                            | Kaitai Struct                         | Output of the format agent                     | M5        |
| Benchmarks                              | LLM4Decompile and its data            | Comparison with the state of the art           | M3        |

## Milestones

### M0 — Foundations · done

- TypeScript project: strict type checking, ESLint, Prettier, Vitest, CI (`npm run check`).
- Schemas for nodes, edges and evidence, beside the hypothesis schema.
- Graph store with the integrity rules (`docs/ARCHITECTURE.md`, Knowledge graph) and a byte-stable JSONL
  export and import.
- **Done when:** CI green; a graph is written, read, exported and re-imported identically. Met: 14 tests.

### M1 — Clone, set up, load a binary · 1–2 weeks

- `scripts/setup.sh`: installs Atlas, REA and Ghidra (with its Java) in one command, checks each, and names what is
  missing and how to get it. Idempotent: a second run changes nothing.
- REA adapter (`src/tools/rea/`): open a binary, list functions, calls and strings, each with its REA evidence.
- Loader that fills the graph from it.
- CLI with `--json` output (`src/cli/`): `atlas load`, `atlas get function`, `atlas list callers`, `atlas export`.
- "Getting started" at the top of `AGENTS.md`: clone, set up, first commands.
- **Ground-truth target:** Lua, built twice from its sources (with symbols, stripped), fixture in
  `tests/fixtures/lua/`. The symbols are the answer key for every later score.
- **Done when:**
  - the graph's functions and calls on the stripped build match Ghidra's view, checked by test;
  - a fresh AI session given only the repository's address sets Atlas up and queries Lua's graph by itself.

### M2 — First agent, scoring, MCP · 1–2 weeks

- CLI commands to propose hypotheses (`atlas propose name ...`) and to read a task's context from the graph.
- Symbol checker: names scored against the symbol build, the result written by the verification path.
- An outside AI (Claude Code first, then another vendor) names Lua's functions through the CLI.
- MCP server (`src/mcp/`) over the same commands.
- **Done when:** a measured accuracy (share of correct names) on Lua, for at least two AI vendors, through the CLI;
  the same commands answer through MCP.

### M3 — Verification loop · 2–4 weeks

- Rewriter agent: function to C.
- Checks: recompile and compare (objdiff); differential testing on generated inputs; equivalence (Z3, angr) for
  small functions. Failures go back to the agent with the diff, up to a retry budget, then become unknowns.
- **Done when:** a measured share of Lua's functions rewritten and verified, and no hypothesis marked `verified`
  that the symbol build contradicts.

### M4 — Types and traces · 2–3 weeks

- Frida traces projected onto the graph (calls, arguments, memory accesses).
- Typer agent, checked against every observed access.
- **Done when:** measured share of correct struct layouts on Lua's known types.

### M5 — Systems · 2–3 weeks

- Clustering functions into systems; a summary per system.
- Format agent: file format inferred from its loader, Kaitai parser checked on every file of that kind.
- **Done when:** Lua's modules recovered as systems, scored against its source files.

### M6 — Orchestrator: many agents at once · 2–3 weeks

- Atlas runs agents itself, through model APIs (several providers behind one setting), in parallel, with priorities,
  a per-task and a per-project budget.
- **Done when:** all of Lua named and typed by parallel agents, with accuracy and cost measured against M2's single
  assistant.

### M7 — Knowledge carried over

- Fuzzy matching against documented binaries (other versions, open-source libraries); matches imported as
  hypotheses and checked.
- **Done when:** a second Lua version starts from the first one's graph, with the gain in cost measured.

### M8 — Scale

- A large open-source program with its sources (a full game), still scorable; then real targets the operator is
  authorised to analyse.

## Open decisions

- Model API access and budget for M6: which providers, which keys, what monthly cap. Not needed before.
- `node:sqlite` is still flagged experimental in Node 22 (it prints a warning). Kept because it needs no native
  build; to revisit if its API changes.
