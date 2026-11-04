# Atlas architecture

Status: M0 (foundations) done: the graph layer (`src/graph/`). Everything else is design. The plan and its order are
in [`ROADMAP.md`](ROADMAP.md). Estimates below are guesses, not measurements.

## Goal

Cut the reverse engineering of a large program from years to weeks by splitting the work into many small,
checkable hypotheses that AI agents produce in parallel and a verification loop accepts or rejects.

## The problem: what current tools and methods miss

Worked through on a hypothetical large modern game (hundreds of thousands of functions, its own engine with a long
lineage), the case Atlas is designed for.

| Stage                      | Tools today                                           | Weaknesses                                                                                                                                                               |
| -------------------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Disassembly, decompilation | IDA Pro + Hex-Rays, Ghidra, Binary Ninja              | Pseudocode unreadable without names and types; one function at a time, no global view; indirect calls (C++ virtual methods) poorly resolved, so the call graph has holes |
| Types and structures       | Hand reconstruction, RTTI readers, headers            | The slowest work: guessed field by field, and errors spread silently                                                                                                     |
| Library recognition        | FLIRT, Ghidra FunctionID, BinDiff                     | Exact signatures: fail when the compiler, version or options differ; nothing for custom code                                                                             |
| Dynamic analysis           | x64dbg, WinDbg, Frida, Cheat Engine, ReClass          | Manual, breakpoint by breakpoint; what is learned stays in the analyst's head                                                                                            |
| Graphics                   | RenderDoc, PIX, Nsight                                | Excellent on one frame, but no link from a draw call back to the code that issued it                                                                                     |
| File formats               | 010 Editor, Kaitai Struct, community tools            | One format at a time, by hand; formats change between versions                                                                                                           |
| Matching decompilation     | decomp.me, objdiff, m2c                               | Needs the exact compiler; impractical with LTO and PGO                                                                                                                   |
| AI                         | Chat assistants, LLM4Decompile, disassembler plug-ins | One function at a time, no project context, no checking: hallucinated names and types                                                                                    |

Flawed methods behind those gaps, each answered by a principle below:

1. **Bottom-up by default:** starting from functions drowns in their number. Answer: principle 3.
2. **Static and dynamic kept apart:** the debugger knows the values, the decompiler the structure, nothing joins
   them. Answer: principle 4.
3. **Knowledge not shared or structured:** names and types scattered across one analyst's database, scripts and
   forums. Answer: the knowledge graph.
4. **No proof of correctness:** a name or a type is an unchecked guess, and nobody knows how much of a database is
   wrong. Answer: principle 2 and the verification loop.
5. **AI used as a chat, not as a system:** a function pasted in, an answer believed. Answer: agents fed by the graph,
   checked by the loop.
6. **Engine lineage ignored:** documented earlier versions are not carried over. Answer: principle 5.

## Principles

1. **Agent- and language-agnostic.** Atlas exposes one contract (MCP tools + CLI JSON + JSON Schemas). Any agent,
   in any language, uses the same contract. The implementation language is an internal detail.
2. **Every fact has evidence and a confidence.** `guessed` < `inferred` < `observed` < `verified`. Only the
   verification loop sets `verified`.
3. **Top-down.** Systems first (rendering, physics, audio...), functions only where the task needs them.
4. **Static and dynamic merged.** Execution traces and GPU captures are projected onto the same graph as the
   disassembly.
5. **Knowledge carries over.** Facts from documented binaries (earlier engine versions, open-source libraries)
   are imported as hypotheses by fuzzy matching, then checked.

## Layers

```
 Agents (any vendor)  ──►  Atlas MCP server / CLI (--json)
                               │
         ┌─────────────────────┼──────────────────────────┐
         ▼                     ▼                          ▼
   Orchestrator         Knowledge graph             Verification loop
   (task queue,         (SQLite + JSONL export,     (recompile + compare,
    budgets, agents      schema/*.schema.json)       differential tests,
    over model APIs)                                 type checks on traces)
         │                     ▲                          │
         └──────────► Tools layer: one adapter per engine ◄─┘
                      Ghidra, REA, later Rizin, angr, IDA, Frida
```

### Tools layer: several engines, cross-checked

Each analysis engine is one adapter in `src/tools/<tool>/`; nothing else calls a tool directly. Engines are
cross-checked: a fact two engines agree on carries both pieces of evidence, a disagreement becomes an unknown.

- **Ghidra headless** (`src/tools/ghidra/`), driven directly: the first engine, so Atlas depends on no wrapper.
- **[REA](https://github.com/morluto/rea)** (`src/tools/rea/`, MIT): one MCP interface over Ghidra, IDA, Hopper,
  JEB, Rizin and objdump, many format parsers, dynamic tools, evidence records (`ev_...` with limitations and
  unknowns). Second engine, used under the conditions of its review (`docs/DEPENDENCY_REVIEWS.md`).
- Later: Rizin directly, angr, IDA for operators with a licence. Atlas adds tools of its own only where scores on
  ground-truth targets show a gap, and only if they beat the tool they replace (`docs/ROADMAP.md`, End goal).

What no engine does, and Atlas adds: a durable graph, the hypothesis verification loop, orchestration of many
agents, clustering into systems, trace projection, knowledge carried over between binaries.

### Knowledge graph

- **Nodes:** `binary`, `function`, `type`, `global`, `system`, `format`, `shader`, `resource`, `unknown`.
- **Edges:** `calls`, `reads`, `writes`, `contains`, `draws`, `loads`, `matches` (to a documented binary).
- **Facts on nodes** (name, signature, type, summary) are hypotheses (`schema/hypothesis.schema.json`), each
  with evidence and confidence. Conflicting hypotheses coexist until verification settles them.
- **Storage:** SQLite (one file per project, Node's built-in `node:sqlite`: no native dependency), exportable to
  JSONL in a fixed order so two exports of one graph are byte-identical and can be diffed, reviewed and shared like
  code. Schemas are versioned (`schema_version`).
- **What the store enforces beyond the schemas** (`src/graph/graph-store.ts`): an ID's prefix matches its kind;
  every non-binary node names a binary in the graph; edges and hypotheses reference existing nodes; agents propose
  hypotheses (`proposeHypothesis`) but cannot set `verified`, `rejected` or the verification result, which only the
  verification loop writes (`recordVerification`); an import restores a reviewed export as is, in one transaction.

### Orchestrator

- Turns a goal ("understand the rendering") into tasks on graph nodes, by priority (hot code from traces first,
  the goal's system first).
- Until it exists (roadmap M6), the agent is the operator's own AI, reaching Atlas by the CLI or MCP
  (`docs/ROADMAP.md`, How an AI uses Atlas). Then it runs agents as model API calls in parallel, not as chat
  sessions. Each task gets its context from the graph:
  the node, its neighbours, observed values, current hypotheses.
- Enforces a compute budget per project and per task.

Agent roles: **namer**, **typer**, **rewriter** (function to C), **summariser** (per system), **format reader**
(infers a file format from its loader, emits a Kaitai description).

### Verification loop

Each hypothesis goes to the checker that fits it:

| Hypothesis         | Check                                                                                                                                                            |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rewritten function | Recompile, then structural equivalence (control-flow graph, solver on small functions) or differential testing against the original on inputs recorded in traces |
| Type / structure   | Every observed memory access in traces must fit it                                                                                                               |
| Name               | Cross-check with strings, leftover symbols, matched functions in documented binaries                                                                             |
| File format        | The generated parser must read every file of that kind in the target                                                                                             |

Pass raises confidence; fail goes back to the agent with the failure, up to a retry budget, then becomes an
`unknown`.

### Dynamic data

- Execution traces (functions called, arguments, memory touched) from Frida or an emulator, projected onto the
  graph. Observed values give types (a field always a float in [0, 1] is likely a ratio), the real targets of
  indirect calls, and which code is hot or dead.
- GPU captures linked to code: each draw call traced to the function that issued it, so "this pass costs 4 ms"
  becomes "this function of the shadows system".

### Systems (top-down)

Functions are clustered into systems (rendering, physics, AI, audio, streaming, network, scripting) by call graph,
shared data, the strings and resources they touch, and when they run. The operator starts from a map of tens of
systems, not hundreds of thousands of functions, and goes down only where the goal needs it.

### Knowledge carried over

Fuzzy matching (code embeddings, not exact signatures) between the target and documented binaries: earlier
versions of the same engine, open-source libraries, middleware SDKs. Each match imports names and types as
hypotheses for the verification loop to confirm or reject. On an engine with a long lineage, much of the code
arrives partly named.

### File formats

The format agent infers a format from the code that reads it (the loader shows the structure) and emits a Kaitai
description; the parser generated from it must read every file of that kind in the target.

### Question interface

The operator asks questions ("where is traffic density computed?", "what costs most in night rendering?"), and Atlas
answers with graph nodes, their confidence and their evidence, not with a disassembly listing.

## Expected gains

Guesses for a large target once Atlas is built, to be replaced by measurements (roadmap M2 onward):

| Task                           | Today, large team | With Atlas                       |
| ------------------------------ | ----------------- | -------------------------------- |
| Map the systems                | Months            | Days                             |
| Name and type most of the code | Years             | Weeks                            |
| Understand one targeted system | Months            | Days to weeks                    |
| Checked rewrite of one system  | Months to years   | Weeks                            |
| Full checked rewrite           | Not realistic     | Very long, possible in principle |

## Limits

- Differential testing needs the original code runnable in a controlled environment; its coverage is the
  traces' coverage.
- Heavy optimisation (LTO, PGO, inlining) blurs function boundaries and weakens matching.
- Compute cost grows with the number of functions times agent passes.
- Compiled code of a third-party program cannot be redistributed: only tools and graphs built by each operator.
- Understanding intent stays partly human; summaries help, they do not replace review.
- Getting at protected code (encryption, anti-tamper) is out of scope.

## Development order

The milestones, what each delivers and how it is judged done: [`ROADMAP.md`](ROADMAP.md).
