#!/usr/bin/env -S node --disable-warning=ExperimentalWarning
// Atlas's command line. Every command answers in JSON with --json (the form agents read, AGENTS.md section 1) and
// in short text otherwise. Exit code 0 on success, 1 on a failure the output describes, 2 on a usage error.
import { parseArgs } from "node:util";
import { GraphStore, TaskClaims } from "../graph/index.js";
import { ARCHITECTURES } from "../tools/engine-analysis.js";
import { runClusterSystems, runGetSystem, runProposeSummary } from "./commands/systems.js";
import { runInferFields, runInferTypes } from "./commands/infer.js";
import { runLift } from "./commands/lift.js";
import { runRepair } from "./commands/repair.js";
import { runMatchGraph } from "./commands/match-graph.js";
import { runCheckFormat } from "./commands/format.js";
import { runTrace } from "./commands/trace.js";
import {
  runBlameBehaviour,
  runCopyBehaviour,
  runCoverageBehaviour,
  runFuzzBehaviour,
  runRecordBehaviour,
  runVerifyBehaviour,
} from "./commands/behaviour.js";
import { runCheckFunctions } from "./commands/check.js";
import { runExport } from "./commands/export.js";
import { runGetFunction } from "./commands/get-function.js";
import { runList } from "./commands/list.js";
import { parseRaw, runLoad } from "./commands/load.js";
import { runClaimTask, runReleaseTask } from "./commands/claim.js";
import { runPlanAgents } from "./commands/plan.js";
import { runMatchLibraries } from "./commands/libraries.js";
import { runRun } from "./commands/run.js";
import { runProposeName, runScoreNames } from "./commands/names.js";
import { runGetTask, runListTasks } from "./commands/task.js";
import { runDecompile, runDetectToolchain, runProposeRewrite, runVerify } from "./commands/rewrite.js";
import { CliError, fail, print, type Output } from "./output.js";

const USAGE = `usage: atlas <command> [--graph <file>] [--json]

  run <file> --goal "<goal>" [--arch <a> --base <0x..>] [--report <file.md>]
                                    the whole job: load, decompile, detect the toolchain, match libraries,
                                    verify, and report what is verified, linked and still open
  load <binary> [--arch <a> --base <0x..>]
                                    analyse a binary with every available engine and add it to the graph;
                                    --arch and --base for raw bytes with no header (a 3DS code.bin), where
                                    <a> is one of ${ARCHITECTURES.join(", ")}
  get function <fn_id|0xaddress>    a function with its callers, callees, strings and hypotheses
  get task rewrite <fn_id|0xaddress>
                                    everything an agent needs to rewrite the function: original and
                                    attempts' instructions, toolchain, callees' prototypes, the commands
  list tasks rewrite [--binary <bin_>]
                                    the functions still to rewrite, callees before callers
  plan agents --mode adaptive|high|medium|low [--agents <n>]
                                    which model each subagent gets and the claim command it loops on:
                                    adaptive (Haiku, Sonnet, Opus by difficulty), high (all Opus),
                                    medium (Sonnet, Opus), low (Haiku, Opus for what Haiku gives back)
  claim task rewrite --agent <name> [--level <k> --of <n> --bounds <b1,b2>] [--released] [--lease <seconds>]
                                    the next open task nobody holds, callees first, with its full context
                                    and the notes earlier agents left, held until the lease ends (30
                                    minutes by default); --released: only tasks others gave back
  release task <fn_id> --agent <name> [--note "<what was found>"] [--of <n> --bounds <b1,b2>] [--budget <n>]
                                    give a claimed task back, with what was found for the next agent; at
                                    the top level, once --budget agents (2 by default) gave it up, it is
                                    closed as an unknown
  list callers <fn_id|0xaddress>    the functions calling it
  list callees <fn_id|0xaddress>    the functions it calls
  list functions                    every function in the graph
  export [<file.jsonl>]             the graph as JSONL (stdout without a file)

  decompile <file> [--arch <a> --base <0x..>] [--function <fn|0x>]...
                                    Ghidra's C for the binary's functions (all without --function), added
                                    as rewrite hypotheses; load the file first
  match libraries [--library <file.a>]...
                                    recognise functions of static libraries (the detected toolchain's own,
                                    and any given): matched code is linked, not rewritten
  match graph <documented graph.sqlite>
                                    carry knowledge over from a related binary's graph (earlier version,
                                    build with symbols): similar functions get its names and verified
                                    rewrites as hypotheses (rewrites are then checked: atlas verify all)
  propose name <fn|0x> <name> [--agent <name>]
                                    an agent's name for a function (--agent: who proposes it)
  score names --truth <unstripped file>
                                    score the names proposed against the unstripped build's symbols
                                    (ground-truth targets only); records each as verified or rejected
  propose rewrite <fn|0x> --source <file.c> --name <function> [--prelude ghidra] [--agent <name>]
                  [--last <fn|0x> --last-name <function>]
                                    an agent's C for a function, or with --last for the run of neighbouring
                                    functions up to that one (when they jump to each other)
  detect toolchain <file> [--arch <a> --base <0x..>]
                                    how the binary was compiled: compiler clues in the file, then a probe
                                    recompiling a sample of Ghidra's C with each candidate; load and
                                    decompile the file first
  check functions <file> [--arch <a> --base <0x..>]
                                    a second engine (Rizin) lists the functions too: how many entries both
                                    engines agree on, which only one finds; recorded as evidence
  check format <file.ksy> <files...> [--agent <name>] [--binary <bin_>]
                                    a file format described in Kaitai Struct (.ksy), as a format node and
                                    hypothesis; verified when its parser reads every file given
  cluster systems                   group the functions into systems (the source modules they came from)
  get system <sys_id>               a system's functions, strings and calls out, and its summaries
  propose summary <sys_id> "<what it does>" --name <name> [--agent <name>]
                                    an agent's name and summary for a system
  infer fields <program> [--function <fn|0x>]...
                                    the fields each function reads or writes through its pointer arguments
                                    (angr, symbolic; x86-64 ELF), checked against traces when there are some
  infer types [--binary <bin_>]     struct types assembled from the inferred fields: arguments that access
                                    mostly the same fields share one struct (ty_ nodes, type hypotheses)
  record behaviour <program> [--stdin <text>] [--input <file>]... [--output <name>]... [--env K=V]...
                   [--vary <regex>]... [-- <args>]
                                    RUN the original twice on a scenario (fresh directory, fixed environment):
                                    its output, exit and the output files named, recorded as an observed
                                    behaviour, the acceptance test of the whole program; refused if the two
                                    runs differ, beyond the parts --vary masks (a time...)
  copy behaviour <reference> <target>
                                    the behaviours of one build carried to another build of the same
                                    program (another platform), as inferred: their acceptance tests there
  coverage behaviour <original>      RUN the rebuilt program on every recorded behaviour: how many translated
                                    functions they reach, what each adds, the largest none reaches (x86-64)
  fuzz behaviour <original> <reconstruction> [--rounds <n>] [--seed <n>]
                                    RUN both on mutants of the recorded inputs (standard input, input
                                    files; seeded): each one the original repeats but the reconstruction
                                    answers otherwise is recorded as a behaviour, ready for blame
  blame behaviour <original> <hyp_id>
                                    the functions a behaviour the rebuilt program fails comes from: delta
                                    debugging, each probe a rebuild with the other functions run as the
                                    original's machine code; the faulty one marked likely, with the
                                    translated callers on its path (x86-64 Linux; RUNS the program)
  verify behaviour <original> <reconstruction>
                                    RUN the reconstruction on every recorded scenario: reproduced exactly,
                                    verified; else where it differs
  trace <program> [--stdin <text>] [-- <arguments>]
                                    RUN the program under Frida (only one you chose to run): which functions
                                    ran, and per function whether its argument registers held pointers or
                                    integers, recorded as observed signatures (x86-64 Linux)
  lift <file> --out <dir> [--link] [--arch <a> --base <0x..>]
                                    the "it runs" path: every function translated mechanically to C
                                    (through VEX, any architecture) with its runtime and a dispatch table,
                                    and the reasons for the functions it could not translate; with --link
                                    a program for this host built from them: x86-64, verified rewrites in
                                    their place; 32-bit ARM (static ELF), system calls emulated; a Windows
                                    x64 program, its C library and kernel32 served
  repair rewrite <hyp_id|all> [--cc <compiler> --cflags="<flags>"]
                                    before an agent: try the usual fixes (static, noreturn, attributes,
                                    types, operand order) on rewrites that compile to different bytes, keep
                                    the edits that bring the code closer; a better source is proposed and
                                    verified (all: each function's closest near miss)
  verify <hyp_id|all> [--cc <compiler> --cflags="<flags>"] [--equivalence] [--differential]
                                    recompile a rewrite with the target's toolchain and compare it with
                                    the original bytes; records verified, or the failure and its details;
                                    without --cc, the toolchain detected for the binary; with
                                    --equivalence (one hypothesis), different bytes are then checked for
                                    the same behaviour by symbolic execution (angr; x86-64; callees opaque);
                                    with --differential, by running both on generated inputs (observed)

  --graph <file>   the graph database (default: $ATLAS_GRAPH, else ./atlas.sqlite)
  --binary <bin_>  with an address, the binary it belongs to when the graph holds several
  --json           machine-readable output`;

async function withClaims<T>(graphPath: string, work: (claims: TaskClaims) => Promise<T>): Promise<T> {
  const claims = new TaskClaims(graphPath);
  try {
    return await work(claims);
  } finally {
    claims.close();
  }
}

async function main(argv: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        graph: { type: "string" },
        binary: { type: "string" },
        arch: { type: "string" },
        function: { type: "string", multiple: true },
        source: { type: "string" },
        name: { type: "string" },
        prelude: { type: "string" },
        last: { type: "string" },
        "last-name": { type: "string" },
        cc: { type: "string" },
        cflags: { type: "string" },
        equivalence: { type: "boolean" },
        differential: { type: "boolean" },
        stdin: { type: "string" },
        input: { type: "string", multiple: true },
        output: { type: "string", multiple: true },
        env: { type: "string", multiple: true },
        timeout: { type: "string" },
        vary: { type: "string", multiple: true },
        rounds: { type: "string" },
        seed: { type: "string" },
        out: { type: "string" },
        link: { type: "boolean" },
        truth: { type: "string" },
        agent: { type: "string" },
        lease: { type: "string" },
        released: { type: "boolean", default: false },
        level: { type: "string" },
        of: { type: "string" },
        bounds: { type: "string" },
        mode: { type: "string" },
        agents: { type: "string" },
        budget: { type: "string" },
        note: { type: "string" },
        goal: { type: "string" },
        report: { type: "string" },
        library: { type: "string", multiple: true },
        base: { type: "string" },
        json: { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (error) {
    process.stderr.write(`${(error as Error).message}\n${USAGE}\n`);
    return 2;
  }
  const { values, positionals } = parsed;
  const json = values.json === true;
  const [command, ...rest] = positionals;
  if (values.help === true || command === undefined) {
    process.stdout.write(`${USAGE}\n`);
    return command === undefined && values.help !== true ? 2 : 0;
  }

  const graphPath = values.graph ?? process.env.ATLAS_GRAPH ?? "atlas.sqlite";
  const store = new GraphStore(graphPath);
  try {
    let output: Output;
    switch (command) {
      case "load":
        output = await runLoad(store, rest, values.arch, values.base);
        break;
      case "get":
        output =
          rest[0] === "task"
            ? await withClaims(graphPath, (claims) => runGetTask(store, claims, rest.slice(1), values.binary))
            : rest[0] === "system"
              ? runGetSystem(store, rest.slice(1))
              : runGetFunction(store, rest, values.binary);
        break;
      case "list":
        output =
          rest[0] === "tasks" ? runListTasks(store, rest.slice(1), values.binary) : runList(store, rest, values.binary);
        break;
      case "decompile": {
        const { raw } = parseRaw(values.arch, values.base);
        output = await runDecompile(store, rest, raw, values.function ?? [], values.binary);
        break;
      }
      case "run": {
        const { raw } = parseRaw(values.arch, values.base);
        output = await runRun(store, rest, {
          ...(values.goal !== undefined ? { goal: values.goal } : {}),
          ...(values.report !== undefined ? { report: values.report } : {}),
          ...(raw !== undefined ? { raw } : {}),
        });
        break;
      }
      case "claim":
      case "release": {
        const claims = new TaskClaims(graphPath);
        try {
          output =
            command === "claim"
              ? await runClaimTask(store, claims, rest, {
                  ...(values.agent !== undefined ? { agent: values.agent } : {}),
                  ...(values.lease !== undefined ? { lease: values.lease } : {}),
                  ...(values.binary !== undefined ? { binary: values.binary } : {}),
                  released: values.released === true,
                  ...(values.level !== undefined ? { level: values.level } : {}),
                  ...(values.of !== undefined ? { of: values.of } : {}),
                  ...(values.bounds !== undefined ? { bounds: values.bounds } : {}),
                })
              : runReleaseTask(store, claims, rest, {
                  ...(values.agent !== undefined ? { agent: values.agent } : {}),
                  ...(values.note !== undefined ? { note: values.note } : {}),
                  ...(values.of !== undefined ? { of: values.of } : {}),
                  ...(values.bounds !== undefined ? { bounds: values.bounds } : {}),
                  ...(values.budget !== undefined ? { budget: values.budget } : {}),
                });
        } finally {
          claims.close();
        }
        break;
      }
      case "plan":
        output = runPlanAgents(rest, graphPath, {
          ...(values.mode !== undefined ? { mode: values.mode } : {}),
          ...(values.agents !== undefined ? { agents: values.agents } : {}),
          ...(values.bounds !== undefined ? { bounds: values.bounds } : {}),
        });
        break;
      case "match":
        output =
          rest[0] === "graph"
            ? await runMatchGraph(store, rest, values.binary)
            : await runMatchLibraries(store, rest, values.library ?? [], values.binary);
        break;
      case "score":
        output = await runScoreNames(store, rest, values.truth, values.binary);
        break;
      case "lift": {
        const { raw } = parseRaw(values.arch, values.base);
        output = await runLift(store, rest, values.out, raw, values.link === true);
        break;
      }
      case "repair":
        output = await runRepair(store, rest, {
          ...(values.cc !== undefined ? { cc: values.cc } : {}),
          ...(values.cflags !== undefined ? { cflags: values.cflags } : {}),
          ...(values.binary !== undefined ? { binary: values.binary } : {}),
        });
        break;
      case "cluster":
        output = runClusterSystems(store, rest, values.binary);
        break;
      case "propose":
        if (rest[0] === "summary") {
          output = runProposeSummary(store, rest, values.name, values.agent);
          break;
        }
        if (rest[0] === "name") {
          output = runProposeName(store, rest, values.binary, values.agent);
          break;
        }
        output = runProposeRewrite(store, rest, {
          ...(values.source !== undefined ? { source: values.source } : {}),
          ...(values.name !== undefined ? { name: values.name } : {}),
          ...(values.prelude !== undefined ? { prelude: values.prelude } : {}),
          ...(values.binary !== undefined ? { binary: values.binary } : {}),
          ...(values.last !== undefined ? { last: values.last } : {}),
          ...(values["last-name"] !== undefined ? { lastName: values["last-name"] } : {}),
          ...(values.agent !== undefined ? { agent: values.agent } : {}),
        });
        break;
      case "copy":
        output = await runCopyBehaviour(store, rest);
        break;
      case "coverage":
        output = await runCoverageBehaviour(store, rest);
        break;
      case "fuzz":
        output = await runFuzzBehaviour(store, rest, {
          ...(values.rounds !== undefined ? { rounds: values.rounds } : {}),
          ...(values.seed !== undefined ? { seed: values.seed } : {}),
        });
        break;
      case "blame":
        output = await runBlameBehaviour(store, rest);
        break;
      case "record":
        output = await runRecordBehaviour(store, rest, {
          ...(values.stdin !== undefined ? { stdin: values.stdin } : {}),
          ...(values.input !== undefined ? { input: values.input } : {}),
          ...(values.output !== undefined ? { output: values.output } : {}),
          ...(values.env !== undefined ? { env: values.env } : {}),
          ...(values.timeout !== undefined ? { timeout: values.timeout } : {}),
          ...(values.vary !== undefined ? { vary: values.vary } : {}),
          ...(values.agent !== undefined ? { agent: values.agent } : {}),
        });
        break;
      case "verify":
        if (rest[0] === "behaviour") {
          output = await runVerifyBehaviour(store, rest);
          break;
        }
        output = await runVerify(store, rest, {
          ...(values.cc !== undefined ? { cc: values.cc } : {}),
          ...(values.cflags !== undefined ? { cflags: values.cflags } : {}),
          ...(values.equivalence === true ? { equivalence: true } : {}),
          ...(values.differential === true ? { differential: true } : {}),
        });
        break;
      case "infer":
        output =
          rest[0] === "types"
            ? runInferTypes(store, rest, values.binary)
            : await runInferFields(store, rest, values.function ?? []);
        break;
      case "trace":
        output = await runTrace(store, rest, values.stdin !== undefined ? { stdin: values.stdin } : {});
        break;
      case "check": {
        if (rest[0] === "format") {
          output = await runCheckFormat(store, rest.slice(1), {
            ...(values.agent !== undefined ? { agent: values.agent } : {}),
            ...(values.binary !== undefined ? { binary: values.binary } : {}),
          });
          break;
        }
        const { raw } = parseRaw(values.arch, values.base);
        output = await runCheckFunctions(store, rest, raw);
        break;
      }
      case "detect": {
        const { raw } = parseRaw(values.arch, values.base);
        output = await runDetectToolchain(store, rest, raw);
        break;
      }
      case "export":
        output = runExport(store, rest);
        break;
      default:
        throw new CliError("usage", `unknown command ${command}\n${USAGE}`);
    }
    print(output, json);
    return 0;
  } catch (error) {
    return fail(error, json);
  } finally {
    store.close();
  }
}

// A reader that stops early (atlas list functions | head) closes the pipe: that is not an error of Atlas.
process.stdout.on("error", (error: NodeJS.ErrnoException) => {
  if (error.code === "EPIPE") process.exit(process.exitCode ?? 0);
  throw error;
});

process.exitCode = await main(process.argv.slice(2));
