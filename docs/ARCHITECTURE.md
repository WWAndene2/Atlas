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
    claims for the       schema/*.schema.json)       differential tests,
    session's agents)                                type checks on traces)
         │                     ▲                          │
         └──────────► Tools layer: one adapter per engine ◄─┘
                      Ghidra, REA, Rizin, angr, Frida, Kaitai; later IDA
```

### Tools layer: several engines, cross-checked

Each analysis engine is one adapter in `src/tools/<tool>/`; nothing else calls a tool directly. Engines are
cross-checked: a fact two engines agree on carries both pieces of evidence, a disagreement becomes an unknown.

- **Ghidra headless** (`src/tools/ghidra/`), driven directly: the first engine, so Atlas depends on no wrapper.
  Version 12.1.4 on Java 21, found through `GHIDRA_INSTALL_DIR`. Each run imports the binary into a temporary
  project at its own addresses (`-loader-imagebase 0`; Ghidra would otherwise rebase position-independent files),
  and Atlas's script `scripts/AtlasExport.java` writes functions, calls and strings as JSON, which the adapter
  validates before use. A raw image with no header (a 3DS `code.bin`, a ROM) is loaded with the CPU and base address
  the operator gives (`atlas load <file> --arch arm-v6k --base 0x100000`); the architecture names are Atlas's own
  (`src/tools/engine-analysis.ts`), mapped to each engine's identifiers in its adapter.
- **[REA](https://github.com/morluto/rea)** (`src/tools/rea/`, MIT): one MCP interface over Ghidra, IDA, Hopper,
  JEB, Rizin and objdump, many format parsers, dynamic tools, evidence records (`ev_...` with limitations and
  unknowns). Second engine, used under the conditions of its review (`docs/DEPENDENCY_REVIEWS.md`).
- angr (`src/tools/angr/`): symbolic equivalence of two machine codes of one x86-64 function, run by
  `atlas verify --equivalence` when a rewrite's bytes differ (`src/orchestrator/check-behaviour.ts`): equivalent
  marks it verified (check `structural`), different records a counterexample, inconclusive (indirect calls, callees of
  unknown arity, input-bounded loops, symbolic addresses) changes nothing. Calls: the rewrite's calls are linked to
  the original's callees (`src/orchestrator/link-calls.ts`: relocation symbol to graph function), each callee is an
  opaque function returning the same value in both versions, and the calls must match in callee and arguments (up
  to the arity in the rewrite's prototypes); what a callee writes to memory is not modelled. `--differential` runs both codes in angr on the same generated
  inputs (edge values, small and random integers, random buffers): same results make the rewrite `observed`, a
  difference records the input. It ends the input-bounded loops the symbolic check cannot.
- Rizin (`src/tools/rizin/`): second engine. `atlas check functions <file>` sets the function entries it finds
  beside the graph's and records the agreement as engine evidence (`src/orchestrator/cross-check-functions.ts`).
  Measured on Lua x86-64: Rizin finds 588 of Ghidra's 805 entries and none Ghidra misses.
- Frida (`src/tools/frida/`): `atlas trace <program> -- <arguments>` runs a loaded x86-64 Linux program and
  hooks every function (`src/orchestrator/trace-target.ts`): one `trace` evidence per run, and per function that
  ran a `signature` hypothesis at `observed` (calls; per argument register pointer, integer or mixed; return).
  Measured on Lua running a script: 256 functions ran, the first argument of 173 Lua functions classified right
  (the three non-pointers are `void`, `unsigned` and a NULL state). Registers past the real arity hold leftovers.
- Kaitai Struct (`src/tools/kaitai/`): `atlas check format <file.ksy> <files...>` records a file format as a
  format node (`fmt_<binary>_<id>`) and a format hypothesis holding the .ksy, then compiles it to a Python parser
  and runs it on every file given (`src/orchestrator/check-format.ts`): all read makes it verified (check
  `parser_run`); a failure records the file and the error; trailing bytes are reported.
- Knowledge carried over (`src/orchestrator/carry-knowledge.ts`): `atlas match graph <documented.sqlite>`
  fingerprints every function of both graphs (instructions with numbers blanked, three at a time; Jaccard
  similarity, `function-fingerprint.ts`) and, for each clear best match (similarity at least 0.2, ahead of the
  second by 0.05), proposes a match, the documented name and any verified rewrite, which the recompile check then
  settles. Measured on Lua x86-64, GCC 11 build with symbols to the stripped GCC 13 build: 380 names, 379 right.
  Across compilers (Clang 17 to GCC 13) it finds little (28 names, 24 right): same compiler family only for now.
- Fields (`src/orchestrator/infer-fields.ts`, `src/tools/angr/fields.py`): `atlas infer fields <program>` runs
  each function in angr from symbolic arguments (callees followed, bounded per function) and records, per pointer
  argument, the fields accessed (offset, width, read/write) as a `signature` hypothesis (inferred, typer/angr);
  checked against Frida traces when present (check `trace_types`).
- Systems (`src/orchestrator/cluster-systems.ts`): `atlas cluster systems` cuts the functions, in address order,
  into contiguous runs maximising modularity over calls plus a link between neighbours (exact dynamic programming);
  each run is a `sys_` node, each member gets a `system` hypothesis (inferred). `atlas get system` gives an agent
  the members, strings and calls out; `atlas propose summary` records its name and summary (`summary` hypothesis).
- Static recompilation, the "it runs" path (`src/tools/vex/`, `src/orchestrator/lift-binary.ts`): `atlas lift
<file> --out <dir>` translates every function's machine code to C through VEX (one translator for x86, x86-64,
  ARM, ARM64, MIPS, PowerPC), with a runtime (`atlas_lift.h`: guest state at VEX's offsets, memory with the guest's
  byte order, x86-64 condition codes, SSE low-lane floating point) and a dispatch table; a whole program recompiles
  before any function is rewritten, and a verified rewrite then replaces its function's translation. Untranslated
  functions are listed with their reason. `check_lifted.py` runs translations and the original (angr) on the same
  inputs (x86-64 so far). Lua: x86-64 687 of 702 functions translated, ARM 1,243 of 1,256, MIPS 869 of 898, PowerPC
  1,094 of 1,097, all compiling; checked on 60 x86-64 functions: 22 same, 0 different, 38 without a valid input.
- Later: IDA for operators with a licence. Atlas adds tools of its own only where scores on
  ground-truth targets show a gap, and only if they beat the tool they replace (`docs/ROADMAP.md`, End goal).

Container formats whose code no engine reads directly are opened by Atlas's own readers before the engines run
(`src/orchestrator/resolve-target.ts`), recognised by their content, not their file name:

- **Nintendo 3DS** (`src/tools/ctr/`): NCSD card images (`.3ds`, `.cci`) and NCCH partitions (`.cxi`). The code
  (ExeFS `.code`, BLZ-decompressed when flagged) is laid out by the extended header's segments and analysed as a
  raw ARMv6K image at the text address. Only decrypted content: an NCCH without the NoCrypto flag is refused,
  because decrypting would bypass the console's copy protection. Written from the community
  documentation (3dbrew) and checked against containers built to that documentation, not yet against a real dump.

- **ZIP-based packages** (`src/tools/zip/`): Android `.apk`/`.aab`, iOS `.ipa`, `.jar`, `.zip`. Every member
  that is an executable (`src/tools/binary-kind.ts`: ELF, PE, Mach-O, DEX, by content) is loaded as its own binary,
  labelled `<package>:<member path>`; a member's path never becomes a path on disk.

Plain executables of any platform the engines read (Windows PE, Linux and Android ELF, macOS and iOS Mach-O, DEX)
go to the engines as they are. A new container format is one reader in `src/tools/<format>/` and one opener in
`resolve-target.ts`.

The Ghidra export script drops two artefacts of Ghidra's analysis, measured on the fixtures: alignment padding
(`nop`, `int3`) after calls that never return, which Ghidra made functions (104 of 1,098 on AArch64), and imports
of dynamically linked files, which Ghidra places in a synthetic `EXTERNAL` block outside the file's bytes.

Every adapter returns the same engine-neutral result (`src/tools/engine-analysis.ts`): functions, calls between
them, strings, and the limitations of the run. The loader (`src/orchestrator/load-binary.ts`) writes it into the
graph: a binary node (`bin_` + the first 16 hex digits of the file's SHA-256), a function node per function
(`fn_<same 16 digits>_<address>`, with `generated: linker` on code in linker-written sections (PLT, init, fini) and
`generated: fragment` on pieces Ghidra found split off another function (its `switchD_...::` namespaces), neither
handed to agents; `thunk: true` on stubs such as import entries, which agents need not name or
rewrite), a `calls` edge per caller and callee pair, a string node (`str_...`) per string with a `reads` edge from each
function using it, all backed by one evidence record
(source `engine`, the engine and its version). Loading again adds evidence instead of replacing it, so a call two
engines found carries both records.

What no engine does, and Atlas adds: a durable graph, the hypothesis verification loop, orchestration of many
agents, clustering into systems, trace projection, knowledge carried over between binaries.

### Knowledge graph

- **Nodes:** `binary`, `function`, `type`, `global`, `string` (its contents in `label`), `system`, `format`, `shader`, `resource`, `unknown`.
- **Edges:** `calls`, `reads` (a function reading a global or a string), `writes`, `contains`, `draws`, `loads`, `matches` (to a documented binary).
- **Facts on nodes** (name, signature, type, summary) are hypotheses (`schema/hypothesis.schema.json`), each
  with evidence and confidence. Conflicting hypotheses coexist until verification settles them.
- **Evidence** (`schema/evidence.schema.json`) names its source. Facts from an engine Atlas runs through its own
  adapter have source `engine` and a `tool` naming the engine and the version that ran (`ghidra` 12.1.4), so any
  engine, Atlas's own included, is recorded without a schema change. REA's records keep source `rea` and their
  `ev_` IDs.
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
- The agents are the operator's own AI session and the subagents it starts, reaching Atlas by the CLI or MCP
  (`docs/ROADMAP.md`, How an AI uses Atlas); Atlas calls no model. Each task gets its context from the graph: the
  node, its neighbours, observed values, current hypotheses.
- In place today: loading a target with every engine that can run here (`load-target.ts`, the engine list in
  `engines.ts`): an engine that is missing or fails is skipped and reported, and loading fails only when none
  succeeds. A function's context (`function-context.ts`): callers, callees, strings read, hypotheses.
- The rewrite work handed to agents: `rewrite-queue.ts` lists a binary's functions not yet covered by a verified
  rewrite (alone or in a run), callees before callers, so callees' prototypes are known when their callers' turn
  comes; `rewrite-task.ts` gives one function's task, self-contained so agents can work in parallel: the original
  instructions (`src/tools/objdump/`, GNU objdump of the architecture), every attempt and its outcome, the closest
  failed attempt's compiled instructions, the toolchain, callers' and callees' verified prototypes, strings,
  neighbours in memory, and the commands to answer with. About 0.25 s per task.

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

In place today, the **recompile check** (`src/verify/recompile/`): a rewrite hypothesis holds a function's C
(`rewrite-value.ts`); `atlas verify` compiles it with the target's toolchain (`--cc`, `--cflags`) and compares the
machine code with the function's `code` in the graph (the file's bytes from its entry to the next function), masking
the bytes relocations fill at link time. Every byte outside them must match: then the hypothesis is `verified`;
otherwise the failure (compile error, or how many bytes differ and where) is recorded for the agent, its confidence
unchanged. Object files are ELF (read with readelf, any architecture) or COFF (Windows toolchains, read by
`object-file.ts`, which also strips the alignment padding COFF sections carry). Validated with Lua's real source
against its builds: x86-64 Linux 152 of 154, ARMv6K 344 of 351, AArch64 Android 385 of 395, x86-64 Windows 106 of
107 (the one: a C library inline, not Lua's). A function that jumps to a neighbour of the same source file (a short
jump the assembler resolved in the original, a relocation when compiled alone) is checked in a **run**: the rewrite
names its `last` function, the source defines the functions from the first to the last in original order, it is
compiled without `-ffunction-sections`, and the run is compared with the graph's code from the first entry to the
end of the last function. Validated: each of Lua's 30 source files, compiled whole, reproduces its run byte for byte. **Toolchain detection** (`src/orchestrator/detect-toolchain.ts`, `atlas detect toolchain <file>`): a real target does
not say how it was compiled. Atlas reads its architecture from the header (recorded on the binary node) and the
compiler version strings left in the file, then probes: Ghidra's C for a sample of the binary's functions is
recompiled with each installed compiler for that architecture at each optimisation level, then with the variants
that matter (ARM or Thumb, float ABI, PIC for libraries), and the candidate reproducing the most functions becomes a
`toolchain` hypothesis on the binary, with its score and the candidates it tied with. `atlas verify` uses it when no
`--cc` is given. Measured on Lua with no hint: correct compiler and level on all four builds (Linux gcc -O2, Windows
MinGW -O2, Android AArch64 -fPIC -O2, raw ARMv6K -marm -mfloat-abi=hard -O2), in 0.5 to 2.5 minutes; -O3 and the
soft-float variants tie, since most functions compile the same with them. Candidates are every installed release
(setup installs GCC 9 to 14, Clang 14 to 19, and cross compilers for 32-bit Windows, ARM, MIPS and PowerPC); a
compiler named by a version string in the file is preferred, the probe then choosing its flags. Ranking is by exact
matches, then by closeness of code size (near misses count); candidates within 1% are reported as ties and the
conventional choice wins (-O2 before -O3, the base variant first). Measured on eight Lua builds with nothing given
but the file: all right but one, where Clang 15 and 17 tie (no version string, near-identical code; the level is
right), 23 to 96 s each with compiles run in parallel. Limit: only installed compilers are candidates (not MSVC
or console SDKs).

`atlas decompile` gives each function as a whole translation unit (`AtlasDecompile.java`): the definitions of the
types it uses (Ghidra's DataTypeWriter), `extern` declarations of its globals with Ghidra's types, its callees'
prototypes (`noreturn` marked; callees without an analysed signature declared as `T name();`, keeping the return
type), then the body. Measured on the four Lua builds against the body alone: compile errors 1,381 to 466, verified
198 to 225 (Linux 19 to 20, Windows 67 to 85, Android 51 to 60, ARM 61 to 60).

`atlas decompile` adds Ghidra's C for each function as a rewrite with
`prelude: ghidra` (its built-in types, `ghidra-types.h`), the starting point an agent improves.

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

### Library recognition

`atlas match libraries` (`src/orchestrator/match-libraries.ts`) finds the functions of a binary that are code of a
static library: the detected toolchain's own (`libgcc`, the C and maths libraries, MinGW's; found with
`-print-file-name` under the detected flags, so multilib toolchains answer for the right CPU) and any `--library`
given, and the startup objects the linker adds to every program (`crt1.o`/`Scrt1.o`, `crti.o`, `crtbegin*.o`...).
Each library function is its bytes in its object with relocation holes masked (`src/tools/archive/` reads `ar`
archives); x86-64 `GOTPCRELX` relocations also mask the two bytes before the field, which the linker rewrites when
it relaxes a GOT load into a `lea`. A binary's function matches when its code equals those bytes outside the holes,
looked up by its first 8 bytes with the relocated ones zeroed (grouped by which of the 8 are relocated, so a
function starting with an address is found); functions under 12 bytes are not matched; a function with no recorded
size (hand-written assembly) runs to the next symbol. A match is a `match` hypothesis, plus a name when one
library name fits, and takes the function out of the rewrite queue: library code is linked, not rewritten.
Measured: raw ARMv6K Lua (newlib linked statically) 198 functions matched, 153 named, all right; Windows Lua (MinGW
runtime) 100 matched, 96 named, 95 right (the other: two byte-identical trivial functions with different names);
Android Lua 1 (its C library is dynamic: nothing to find); with the startup objects and the index on relocated
prefixes, ARM Lua 206 matched, 159 named, all right, and the benchmark's `_start`, `deregister_tm_clones`,
`register_tm_clones` and `__do_global_dtors_aux` found. A later toolchain detection supersedes an earlier one. The
detection also notes what the imports show of the build: calls to the C library's checked variants (`__memcpy_chk`,
...) mean `_FORTIFY_SOURCE`, which the rewrite task tells agents (`buildNotes`).

### Name scoring

`atlas propose name <fn> <name>` adds a name hypothesis. On a ground-truth target, `atlas score names --truth
<unstripped build>` checks every proposed name against the build's symbols (`src/verify/symbols/`, symbols read by
`src/tools/symbols/`: ELF and PE): verified when equal once compiler additions are removed (leading underscores,
`.isra`, `.constprop`, `.part`, `.cold`), rejected otherwise, inconclusive where the key has no symbol. Functions whose
true name is already their label (exported symbols left in a stripped binary: 155 of 706 on Lua) are counted apart,
so the accuracy measures naming, not reading.

### The whole job

`atlas run <file> --goal "<goal>" [--report <file.md>]` (`src/orchestrator/run-target.ts`) chains every step on
each binary the file holds: load with every engine, decompile, detect the toolchain, match libraries, verify every
rewrite, and report per binary the toolchain and its evidence, the functions that are stubs, library code, verified,
and still open, the first open ones callees first, the time of each step, and any step that could not run (the run
goes on without it). Agents working the open tasks in parallel (roadmap M6) will come between verification and the
report. Raw ARM Lua: 881 functions, 9 stubs, 198 library, 60 verified, 618 open, in about 3 minutes.

### MCP server

`atlas-mcp [--graph <file>]` (`src/mcp/`, over stdio; launcher installed by setup) offers the CLI's operations as MCP
tools in the same vocabulary (`run`, `load`, `get_function`, `list_functions`, `list_callers`, `list_callees`,
`decompile`, `detect_toolchain`, `match_libraries`, `list_tasks_rewrite`, `get_task_rewrite`, `propose_rewrite`,
`propose_name`, `verify`, `export`), calling the same orchestrator functions. Each answers one JSON document; an error
is an error result holding `{"error": {"message"}}`. Built on the official MCP TypeScript SDK (1.32.2, MIT).

### Parallel agents

Atlas calls no model: the operator's AI session starts subagents, and Atlas coordinates them. `atlas claim task
rewrite --agent <name>` gives the next open task nobody holds, callees first, with its full context, under a lease
(30 minutes by default) recorded in a `claims` table beside the graph (`src/graph/task-claims.ts`, never exported);
a verified task leaves the queue, a lapsed one returns to it, and a released one returns behind every task not yet
tried, with the note its agent left (`release --note`; shown in the next claim and in `get task`). `claim --released`
takes only given-back tasks. A task given back at the top level has nowhere to go: each such release counts against a
retry budget (`release-task.ts`; two different agents by default, `release --budget`), and when it runs out the
function's rewrite is recorded as an `unknown` node (`unk_rewrite_<function>`, its label saying so, the agents'
notes kept with its claims) and the function leaves the queue. Agents of different models are routed by **level** (`src/orchestrator/task-levels.ts`):
a task's level is its size tier (bounds 160 and 400 bytes by default, from what each model verified on Lua) plus the
times it was given back, capped at the top; an agent at level k (`claim --level k --of n --bounds ...`) takes only
level-k tasks, so small functions go to the cheapest model and what a level gives back moves up. `atlas plan agents
--mode adaptive|high|medium|low` (`agent-plan.ts`; MCP `plan_agents`, with `claim_task_rewrite` and `release_task`)
gives the session the model and claim command of each subagent: adaptive Haiku/Sonnet/Opus, high Opus, medium
Sonnet/Opus, low Haiku with Opus for what Haiku gives back. Proposals carry the
proposing agent's name (`--agent`), so each agent's (and model's) work can be measured. Several processes share one graph file:
WAL journaling, a 30-second lock wait and immediate transactions keep it consistent (checked with eight claims at
the same moment: eight different tasks). The protocol for sessions is in `AGENTS.md` 1.8.

### Command line

`atlas <command> [--graph <file>] [--json]` (`src/cli/`, built to `dist/src/cli/main.js`): `load`, `get function`,
`list callers|callees|functions`, `export`. Functions are named by ID or by address. With `--json` every answer,
errors included, is one JSON document (`{"error": {"code", "message"}}` on failure); exit code 0 on success, 1 on
a failure, 2 on a usage error. The graph is `--graph`, else `$ATLAS_GRAPH`, else `./atlas.sqlite`.

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
