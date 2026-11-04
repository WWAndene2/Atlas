# Atlas roadmap

The order of development, what each milestone delivers and how it is judged done. Durations are estimates, not
measurements. Update this file when a milestone finishes or the plan changes.

## Principle: write the core, reuse the rest

Only three parts do not exist elsewhere and are written for Atlas: the **knowledge graph**, the **verification
loop** and the **orchestrator**. Everything else is reused, each dependency added at the milestone that needs it,
pinned, with its licence checked when added (AGENTS.md section 8).

| Need                                    | Project                               | Use in Atlas                                   | Milestone |
| --------------------------------------- | ------------------------------------- | ---------------------------------------------- | --------- |
| Analysis tools behind one MCP interface | [REA](https://github.com/morluto/rea) | Tools layer (`src/tools/rea/`)                 | M1        |
| Free decompiler                         | Ghidra, through REA                   | Default engine: no commercial licence required | M1        |
| Light disassembly                       | Rizin, through REA                    | Fast analysis, CI                              | M1        |
| MCP server                              | Official MCP TypeScript SDK           | Atlas's public interface (`src/mcp/`)          | M1        |
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

### M1 — Graph from a binary, no AI · 1–2 weeks

- REA adapter: open a binary, list functions, calls and strings, each with its REA evidence.
- Loader that fills the graph from it.
- Read-only MCP server and CLI (`get_function`, `list_callers`, `export_graph`).
- **Ground-truth target:** Lua, built twice from its sources (with symbols, stripped), fixture in
  `tests/fixtures/lua/`. The symbols are the answer key for every later score.
- **Done when:** the graph's functions and calls on the stripped build match Ghidra's view, checked by test.

### M2 — First agent and scoring · 1–2 weeks

- Orchestrator skeleton: tasks over graph nodes, one model call per task, per-task budget.
- Namer agent: context from the graph, hypotheses out.
- Symbol checker: names scored against the symbol build.
- **Done when:** a measured accuracy (share of correct names) and cost per function on Lua.

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

### M5 — Systems and orchestration at scale · 2–3 weeks

- Clustering functions into systems; a summary per system; tasks in parallel with priorities and a project budget.
- Format agent: file format inferred from its loader, Kaitai parser checked on every file of that kind.
- **Done when:** Lua's modules recovered as systems, scored against its source files.

### M6 — Knowledge carried over

- Fuzzy matching against documented binaries (other versions, open-source libraries); matches imported as
  hypotheses and checked.
- **Done when:** a second Lua version starts from the first one's graph, with the gain in cost measured.

### M7 — Scale

- A large open-source program with its sources (a full game), still scorable; then real targets the operator is
  authorised to analyse.

## Open decisions

- Model API access and budget for M2 onward: which provider, which key, what monthly cap.
- `node:sqlite` is still flagged experimental in Node 22 (it prints a warning). Kept because it needs no native
  build; to revisit if its API changes.
