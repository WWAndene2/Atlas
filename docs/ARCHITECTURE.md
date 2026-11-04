# Atlas architecture

Status: M0 (foundations) done: the graph layer (`src/graph/`). Everything else is design. The plan and its order are
in [`ROADMAP.md`](ROADMAP.md). Estimates below are guesses, not measurements.

## Goal

Cut the reverse engineering of a large program from years to weeks by splitting the work into many small,
checkable hypotheses that AI agents produce in parallel and a verification loop accepts or rejects.

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
         └──────────► Tools layer: REA (MCP) ◄────────────┘
                      Ghidra, IDA, Rizin, JEB, Frida, parsers, captures
```

### Tools layer: REA

[REA](https://github.com/morluto/rea) (MIT) already gives one MCP interface over Ghidra, IDA, Hopper, JEB, Rizin
and objdump, many format parsers, dynamic tools, evidence records (`ev_...` with limitations and unknowns),
an unknowns ledger and function comparison. Atlas calls it; it does not reimplement it.

What REA does not do, and Atlas adds: a durable graph (REA's evidence lives per connection), the hypothesis
verification loop, orchestration of many agents, clustering into systems, trace projection.

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
- Runs agents as model API calls in parallel, not as chat sessions. Each task gets its context from the graph:
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

- Execution traces (functions called, arguments, memory touched) from Frida or an emulator.
- GPU captures linked to code: each draw call traced to the function that issued it.

## Limits

- Differential testing needs the original code runnable in a controlled environment; its coverage is the
  traces' coverage.
- Heavy optimisation (LTO, PGO, inlining) blurs function boundaries and weakens matching.
- Compute cost grows with the number of functions times agent passes.
- Understanding intent stays partly human; summaries help, they do not replace review.
- Getting at protected code (encryption, anti-tamper) is out of scope.

## First milestone

One small open-source binary (built from known sources, so results can be scored against the truth):

1. Load it through REA, build the graph of functions and calls.
2. One namer agent and one typer agent over the graph, through the MCP server.
3. Verification of names against the real symbols (the scoring oracle), and of rewritten functions by
   recompile + differential test.
4. Measure: fraction of functions correctly named and verified, cost per function.
