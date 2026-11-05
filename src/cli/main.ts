#!/usr/bin/env -S node --disable-warning=ExperimentalWarning
// Atlas's command line. Every command answers in JSON with --json (the form agents read, AGENTS.md section 1) and
// in short text otherwise. Exit code 0 on success, 1 on a failure the output describes, 2 on a usage error.
import { parseArgs } from "node:util";
import { GraphStore } from "../graph/index.js";
import { ARCHITECTURES } from "../tools/engine-analysis.js";
import { runExport } from "./commands/export.js";
import { runGetFunction } from "./commands/get-function.js";
import { runList } from "./commands/list.js";
import { parseRaw, runLoad } from "./commands/load.js";
import { runMatchLibraries } from "./commands/libraries.js";
import { runProposeName, runScoreNames } from "./commands/names.js";
import { runGetTask, runListTasks } from "./commands/task.js";
import { runDecompile, runDetectToolchain, runProposeRewrite, runVerify } from "./commands/rewrite.js";
import { CliError, fail, print, type Output } from "./output.js";

const USAGE = `usage: atlas <command> [--graph <file>] [--json]

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
  propose name <fn|0x> <name>       an agent's name for a function
  score names --truth <unstripped file>
                                    score the names proposed against the unstripped build's symbols
                                    (ground-truth targets only); records each as verified or rejected
  propose rewrite <fn|0x> --source <file.c> --name <function> [--prelude ghidra]
                  [--last <fn|0x> --last-name <function>]
                                    an agent's C for a function, or with --last for the run of neighbouring
                                    functions up to that one (when they jump to each other)
  detect toolchain <file> [--arch <a> --base <0x..>]
                                    how the binary was compiled: compiler clues in the file, then a probe
                                    recompiling a sample of Ghidra's C with each candidate; load and
                                    decompile the file first
  verify <hyp_id|all> [--cc <compiler> --cflags="<flags>"]
                                    recompile a rewrite with the target's toolchain and compare it with
                                    the original bytes; records verified, or the failure and its details;
                                    without --cc, the toolchain detected for the binary

  --graph <file>   the graph database (default: $ATLAS_GRAPH, else ./atlas.sqlite)
  --binary <bin_>  with an address, the binary it belongs to when the graph holds several
  --json           machine-readable output`;

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
        truth: { type: "string" },
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

  const store = new GraphStore(values.graph ?? process.env.ATLAS_GRAPH ?? "atlas.sqlite");
  try {
    let output: Output;
    switch (command) {
      case "load":
        output = await runLoad(store, rest, values.arch, values.base);
        break;
      case "get":
        output =
          rest[0] === "task"
            ? await runGetTask(store, rest.slice(1), values.binary)
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
      case "match":
        output = await runMatchLibraries(store, rest, values.library ?? [], values.binary);
        break;
      case "score":
        output = await runScoreNames(store, rest, values.truth, values.binary);
        break;
      case "propose":
        if (rest[0] === "name") {
          output = runProposeName(store, rest, values.binary);
          break;
        }
        output = runProposeRewrite(store, rest, {
          ...(values.source !== undefined ? { source: values.source } : {}),
          ...(values.name !== undefined ? { name: values.name } : {}),
          ...(values.prelude !== undefined ? { prelude: values.prelude } : {}),
          ...(values.binary !== undefined ? { binary: values.binary } : {}),
          ...(values.last !== undefined ? { last: values.last } : {}),
          ...(values["last-name"] !== undefined ? { lastName: values["last-name"] } : {}),
        });
        break;
      case "verify":
        output = await runVerify(store, rest, {
          ...(values.cc !== undefined ? { cc: values.cc } : {}),
          ...(values.cflags !== undefined ? { cflags: values.cflags } : {}),
        });
        break;
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
