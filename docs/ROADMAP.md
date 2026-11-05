# Atlas roadmap

The order of development, what each milestone delivers and how it is judged done. Durations are estimates, not
measurements. Update this file when a milestone finishes or the plan changes.

## End goal

Atlas is a complete reverse-engineering solution: an operator says "use Atlas on <target> to <goal>" and Atlas does
the job by itself, from setting up its tools to a verified result with its evidence. It builds on the best existing
tools and adds its own where they fall short, so the whole does better than any of them alone.

How it gets there:

- **Several engines, cross-checked.** Each analysis tool is one adapter (`src/tools/<tool>/`). A fact two engines
  agree on carries both pieces of evidence; a disagreement becomes an unknown, never a silent choice.
- **Own tools where a gap is measured.** Atlas writes a tool of its own when the scores on the ground-truth targets
  show an existing one falls short (missed functions, wrong types, slow traces), and the replacement must beat it on
  the same score. No own tool without that measured gap.
- **One command for the whole job.** `atlas run <target> --goal "<goal>"` (M9) chains setup, loading, analysis by
  agents, verification and a report, with no step to run by hand.

## How an AI uses Atlas

Atlas calls no AI model itself. The AI is whichever assistant the operator already uses (Claude, GPT,
Gemini...), and it reaches Atlas through one of two doors onto the same engine and graph:

1. **Clone and run (the main door).** The AI is given the repository's address, clones it into its own environment,
   runs `scripts/setup.sh`, then uses the CLI (`--json`), following `AGENTS.md`. For any AI that can run commands
   (Claude Code, Codex, Cursor's agent, Gemini CLI).
2. **MCP.** The AI connects to an Atlas already running somewhere. For AIs that cannot run commands (chat in a
   browser) and for one graph shared by several AIs or people.

Running many agents in parallel comes at M6: subagents of the operator's own AI session, which Atlas coordinates.

## Principle: write the core, reuse the rest

Only three parts do not exist elsewhere and are written for Atlas: the **knowledge graph**, the **verification
loop** and the **orchestrator**. Everything else is reused, each dependency added at the milestone that needs it,
pinned, with its licence checked when added (AGENTS.md section 8).

| Need                                    | Project                               | Use in Atlas                                   | Milestone |
| --------------------------------------- | ------------------------------------- | ---------------------------------------------- | --------- |
| Analysis tools behind one MCP interface | [REA](https://github.com/morluto/rea) | Tools layer (`src/tools/rea/`)                 | M1        |
| Free decompiler                         | Ghidra, through REA                   | Default engine: no commercial licence required | M1        |
| Light disassembly                       | Rizin, through REA                    | Fast analysis, CI                              | M1        |
| MCP server                              | Official MCP TypeScript SDK 1.32.2    | Second door (`src/mcp/`)                       | M2        |
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

### M1 — Clone, set up, load a binary with two engines · 2–3 weeks · in progress

Order of work: (1) REA review, done; (2) Lua fixture, done; (3) Ghidra adapter and loader, done; (4) CLI, done;
(5) setup script, done; (5b) raw images and the ARM fixture, done; (7) getting started in `AGENTS.md` and the
fresh-session test, done (a clean clone sets up in 50 s and loads Lua with the documented commands; not yet run by
another AI vendor); (6) the second engine and cross-check, moved after M3.

Why the change (4 November 2026): the acceptance test is a game reverse engineered and recompiled in days, judged
on time. A second engine raises confidence, not speed; the path to that test runs through raw console images (5b),
naming (M2) and verified rewriting (M3). Measured meanwhile: REA 6.8.0 analyses native Linux binaries only through
Ghidra, so it cannot cross-check Ghidra; the second engine is Rizin directly (0.9.1, independent code base), to be
built from its pinned source since its release publishes no checksum, with REA kept for the targets Ghidra and
Rizin do not cover (JavaScript, .NET, Android, dynamic capture).

- **Security review of REA**, done on 6.8.0 (`docs/DEPENDENCY_REVIEWS.md`): usable as the second engine under
  conditions, so Ghidra's adapter comes first.
- `scripts/setup.sh`: installs Atlas, REA and Ghidra (with its Java) in one command, checks each, and names what is
  missing and how to get it. Idempotent: a second run changes nothing. Done: also builds the Lua fixture and
  installs an `atlas` command; engines go in `~/.local/share/atlas/tools`, where Atlas finds them unconfigured.
  CI runs it, so the Ghidra tests run there.
- Two engine adapters, each listing functions, calls and strings with evidence:
  - `src/tools/ghidra/`: Ghidra headless, driven directly: first, Atlas works with it alone. Done with Ghidra
    12.1.4: on stripped Lua it finds 708 of the 711 functions (one extra), checked by test where Ghidra is
    installed;
  - `src/tools/rea/`: REA 6.8.0 (its formats, its evidence records), installed as its review requires.
- Loader that fills the graph from both and cross-checks them: agreement gives a fact two pieces of evidence,
  disagreement gives an unknown.
- CLI with `--json` output (`src/cli/`): `atlas load`, `atlas get function`, `atlas list callers`, `atlas export`.
  Done, with `atlas list callees` and `atlas list functions`; built to `dist/` (`npm run build`).
- "Getting started" at the top of `AGENTS.md`: clone, set up, first commands.
- **Raw images (5b):** `atlas load --arch --base` for bytes with no header. ARM fixture `tests/fixtures/lua-arm/`:
  Lua for the 3DS's CPU (ARMv6K, hard float) with GCC and newlib, as a raw image at 0x100000. Ghidra on it: recall
  0.82, precision 0.999. Most misses are library code nothing calls and functions reached only through pointers in
  data; a naive pointer-seeding pass gave +0.01 recall for -0.13 precision and was dropped. A better finder
  (prologue patterns, validated seeds) is a candidate for Atlas's own tool, scored on this fixture.
- **3DS titles (5c):** `atlas load game.3ds` opens a decrypted NCSD/NCCH, decompresses the code and loads it as a
  raw ARMv6K image (`src/tools/ctr/`); encrypted content is refused. Checked end to end on the ARM Lua image packed
  as a card image with compressed code (885 functions, 28 s); not yet on a real dump, the first thing to check when
  one is available.
- **PC and mobile (5d):** packages opened into their executables (`src/tools/zip/`), and fixtures for a Windows
  program and an Android package (`tests/fixtures/lua-platforms/`). Measured with Ghidra 12.1.4, recall /
  precision: Linux x86-64 ELF 0.997 / 0.999, Windows PE 0.942 / 0.998, Android AArch64 `.so` in an `.apk` 1.000 /
  0.999 (0.626 before the export script dropped padding and synthetic imports), raw ARMv6K 0.81 / 0.998.
- **Ground-truth target:** Lua, built twice from its sources (with symbols, stripped), fixture in
  `tests/fixtures/lua/`. The symbols are the answer key for every later score. Done: `build.sh` compiles Lua
  5.4.7 (pinned, SHA-256 checked) once and strips a copy, so both files share their code byte for byte (checked
  by test; CI builds it and requires it).
- **Done when:**
  - on the stripped build, the graph's functions and calls are scored against the symbol build for each engine and
    for their combination, checked by test;
  - Atlas still loads Lua with either engine missing;
  - a fresh AI session given only the repository's address sets Atlas up and queries Lua's graph by itself.

### M2 — First agent, scoring, MCP · 1–2 weeks

- CLI commands to propose hypotheses (`atlas propose name ...`) and to read a task's context from the graph.
- Symbol checker: names scored against the symbol build, the result written by the verification path. Done:
  `atlas propose name`, `atlas score names --truth` (free answers counted apart).
- An outside AI (Claude Code first, then another vendor) names Lua's functions through the CLI.
- MCP server (`src/mcp/`) over the same commands. Done: `atlas-mcp`, tested with the SDK's own client.
- **Done when:** a measured accuracy (share of correct names) on Lua, for at least two AI vendors, through the CLI;
  the same commands answer through MCP.

### M3 — Verification loop · 2–4 weeks

- Rewriter agent: function to C.
- Checks: recompile and compare (objdiff); differential testing on generated inputs; equivalence (Z3, angr) for
  small functions. Failures go back to the agent with the diff, up to a retry budget, then become unknowns.
- **Done when:** a measured share of Lua's functions rewritten and verified, and no hypothesis marked `verified`
  that the symbol build contradicts.
- **In progress.** Done: the recompile check (byte-exact, relocations masked; validated on Lua's real source, 152 of
  154), `atlas decompile`, `atlas propose rewrite`, `atlas verify <hyp|all>`. Baseline, Ghidra's C as written on
  x86-64 Lua with GCC -O2: 19 of 709 functions verified, 439 compile but differ, 251 do not compile. First agent trial
  (an AI working only through the CLI, from Ghidra's C and the recorded failure): 6 of 6 randomly sampled failing
  functions of 22 to 59 bytes verified, in 8 attempts; the fixes were struct types and offsets, `noreturn`,
  prototypes and `static` (now in `AGENTS.md`, 1.7). Equivalence (angr 10.0.5 and Z3) is in, opt-in through
  `atlas verify --equivalence`: x86-64 leaf functions with loops bounded independently of the inputs; calls and
  other architectures answer inconclusive. The check now
  works on every platform in view (ELF and COFF objects), validated with Lua's real source on each (97 to 99%), and
  the baseline of Ghidra's C as written: Linux x86-64 19 of 709, Windows x86-64 67 of 819, Android AArch64 51 of 686,
  raw ARMv6K 61 of 872, each checked in about 20 s. Runs of neighbouring functions remove the
  same-file jump limit (all 30 Lua source files reproduce whole). Toolchain detection finds the compiler and flags
  with no hint, among GCC 9 to 14, Clang 14 to 19 and cross compilers for Windows, ARM, MIPS and PowerPC (right on 7
  of 8 Lua builds; the eighth a reported Clang 15/17 tie). MIPS and PowerPC are architectures of their own (the
  PlayStation and GameCube/Wii families). Ghidra's C now comes as whole translation units
  (types, globals, callee prototypes): compile errors down two thirds, verified up 14% on the four Lua builds.
  Agents' work is prepared: `atlas list tasks rewrite` (callees first)
  and `atlas get task rewrite` (one self-contained task per function, original and attempt instructions side by
  side), the input M6's parallel agents will take. Next: the agent loop over a whole binary, larger
  functions, and the share verified and the time it takes.

### M4 — Types and traces · 2–3 weeks

- Frida traces projected onto the graph (calls, arguments, memory accesses).
- Typer agent, checked against every observed access.
- **Done when:** measured share of correct struct layouts on Lua's known types.

### M5 — Systems · 2–3 weeks

- Clustering functions into systems; a summary per system.
- Format agent: file format inferred from its loader, Kaitai parser checked on every file of that kind.
- **Done when:** Lua's modules recovered as systems, scored against its source files.

### M6 — Orchestrator: many agents at once · 2–3 weeks

- Agents of the operator's own AI session, not model APIs (decided 5 November 2026: the operator uses no API
  provider). The session starts subagents; Atlas hands them tasks without overlap and keeps one graph consistent
  across their processes. Done: `atlas claim task rewrite` (a lease per task, callees first), `atlas release task`,
  the protocol in `AGENTS.md` 1.8, the store safe for concurrent processes (WAL, lock waits, immediate
  transactions).
- First parallel run (x86-64 Lua, four subagents of one session, 5 tasks each at most): 5 verified, all by one
  subagent; the three others stalled because the queue handed out linker stubs (the PLT) and switch fragments, and a
  released task came straight back. Fixed: code in linker sections and Ghidra's switch fragments are marked
  `generated` at load and left out of the queue, and a released task goes behind every task not yet tried. Known
  limit: cold fragments Ghidra does not place in a namespace (FUN_00007bf4 on Lua) still reach the queue.
- Second parallel run, the queue fixed (same target and limits, 21 tasks claimed): 18 verified by the subagents, 2
  more once the recompile check stopped taking a function's cold part (`.text.unlikely.<name>`) for its body: 20 of
  21, functions of 29 to 503 bytes, in about 2.5 minutes of wall time for four subagents. Open tasks: 702 to 658.
  The one left: a 1-byte operand-order difference in `test` that 15 source variants did not move.
- Models compared, same target and rules (5 claims, 3 proposals each): Opus 20 of 21 claims verified, Sonnet 3 of 6
  (one agent broke the limits), Haiku 5 of 10 (easy functions, first or second proposal; the largest released
  untried). Token counts per agent: Opus 77k to 122k, Sonnet 72k and 116k, Haiku 144k and 177k; cost per verified
  function not measured (it needs each model's price). Done for tiering: `release --note` (what was found, shown to
  the next agent), `claim --released` (a stronger model takes only what smaller ones gave back). Then four modes (`atlas plan agents
--mode adaptive|high|medium|low`), routed by level (size tier plus times given back).
- Benchmark (`tests/fixtures/bench/`, a 34-function program written for Atlas: structs, bit fields, hash table,
  bytecode interpreter, recursion, callbacks, variadics, doubles, globals, libc), adaptive mode, 3 Haiku + 2 Sonnet +
  1 Opus, then a second Sonnet for what Haiku gave back: 28 of 31 functions verified (90%): Haiku 11 (25 to 114
  bytes), Sonnet 9 (38 to 267, four of them given back by Haiku and verified at the first proposal from its notes),
  Opus 3 (410, 863 and 2,074 bytes), Ghidra's C 5. Open: the interpreter (1,079 bytes), a string join (318), a
  58-byte loop, each a register or block-layout difference with notes. Tokens per agent: Haiku 145k to 156k, Sonnet
  106k to 121k, Opus 155k. Wall time not measured: a usage limit paused the run for hours; after it, each agent
  worked 2.5 to 4.7 minutes, in parallel. Fixed from the run: notes kept on a release after a lapsed lease, an agent
  never handed its own release (it looped at the top level), C runtime startup code matched as library code
  (`_start` had been rewritten in assembly), fortified builds reported to agents. Then the retry budget at the top
  level: once two different top-level agents gave a task up, it is closed as an unknown. Next: each mode measured
  the same way.
- **Done when:** all of Lua named and rewritten by parallel subagents, with the share verified and the time taken
  measured against one agent.

### M7 — Knowledge carried over

- Fuzzy matching against documented binaries (other versions, open-source libraries); matches imported as
  hypotheses and checked.
- Functions of the compiler's runtime and C library (seen on Windows Lua: `___chkstk_ms`, hand-written assembly that no
  C reproduces) recognised as such, and linked from the library instead of rewritten. Done for static libraries
  (`atlas match libraries`: 153 of 153 names right on ARM Lua, 95 of 96 on Windows Lua). Next: libraries the
  toolchain does not ship (a game's engine, SDKs), from a documented build of them.
- **Done when:** a second Lua version starts from the first one's graph, with the gain in cost measured.

### M8 — Scale

- A large open-source program with its sources (a full game), still scorable; then real targets the operator is
  authorised to analyse.

### M9 — "Use Atlas on <target>": the whole job by itself

- `atlas run <target> --goal "<goal>"`: setup, loading, analysis by agents (M6), verification, and a report of what
  was found, with its confidence and evidence, and what stays unknown. Done without the agents: load, decompile,
  toolchain, libraries, verification and the report; the agents' step waits for M6.
- Own tools added where M1-M8's scores showed a gap, each beating the tool it replaces on the same score.
- **Done when:** on a ground-truth target never seen before, one command produces the report, scored against the
  target's sources.

## Open decisions

- `node:sqlite` is still flagged experimental in Node 22 (it prints a warning). Kept because it needs no native
  build; to revisit if its API changes.
