// Runs a loaded program under Frida and records what was seen: one trace evidence for the run, and for each function
// that ran, a signature hypothesis (confidence observed) saying which argument registers held pointers or integers
// and whether it returned a pointer. Types are then grounded in execution rather than in the decompiler's guess:
// an agent rewriting the function reads them in get function. Runs the target natively: the caller asked for it.
import { createHash } from "node:crypto";
import type { GraphStore, Hypothesis } from "../graph/index.js";
import { FRIDA_VERSION, locateFrida, traceProgram, type FunctionTrace } from "../tools/frida/index.js";
import { fileSha256 } from "./file-hash.js";
import { NotFoundError } from "./function-context.js";
import { binaryId } from "./load-binary.js";

const REGISTERS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

export interface TraceSummary {
  binary: string;
  evidence: string;
  exit: string;
  ran: number;
  hooked: number;
  unhooked: number;
  hypotheses: string[];
}

/** pointer / integer / mixed per register, over the sampled calls; zero counts as either. */
function observedSignature(t: FunctionTrace): Record<string, unknown> {
  const args = t.args.map((a, i) => ({
    register: REGISTERS[i],
    seen:
      a.pointer > 0 && a.integer === 0
        ? "pointer"
        : a.integer > 0 && a.pointer === 0
          ? "integer"
          : a.pointer + a.integer === 0
            ? "zero"
            : "mixed",
    pointer: a.pointer,
    integer: a.integer,
    zero: a.zero,
  }));
  return {
    calls: t.calls,
    arguments: args,
    returns:
      t.returned === 0
        ? "unknown"
        : t.result_pointer === t.returned
          ? "pointer"
          : t.result_pointer === 0
            ? "integer"
            : "mixed",
    note: "registers past the function's real arity hold leftovers from earlier code",
  };
}

export async function traceTarget(
  store: GraphStore,
  program: string,
  argv: string[],
  options: { stdin?: string; timeoutS?: number; samples?: number } = {},
  now = new Date(),
): Promise<TraceSummary> {
  const sha = await fileSha256(program);
  const binary = binaryId(sha);
  if (store.getNode(binary) === undefined) throw new NotFoundError(`${program} is not loaded; atlas load it first`);
  if (store.getNode(binary)?.architecture !== "x86_64") throw new Error("tracing covers x86-64 Linux programs for now");
  const functions = store
    .nodesOfKind("function")
    .filter((n) => n.binary === binary && n.address !== undefined && n.generated === undefined && n.thunk !== true);
  const byAddress = new Map(functions.map((f) => [BigInt(f.address as string), f]));
  const result = await traceProgram(locateFrida(), {
    program,
    argv,
    ...(options.stdin !== undefined ? { stdin: options.stdin } : {}),
    functions: [...byAddress.keys()].map(Number),
    ...(options.samples !== undefined ? { samples: options.samples } : {}),
    ...(options.timeoutS !== undefined ? { timeoutS: options.timeoutS } : {}),
  });
  const run = createHash("sha256")
    .update(`${sha}\n${JSON.stringify(argv)}\n${options.stdin ?? ""}`)
    .digest("hex");
  const evidence = `evd_${run.slice(0, 32)}`;
  const entries = Object.entries(result.functions);
  const ran = entries.filter(([, t]) => t.calls > 0);
  store.putEvidence({
    schema_version: 1,
    id: evidence,
    source: "trace",
    tool: { name: "frida", version: FRIDA_VERSION },
    summary:
      `frida ${FRIDA_VERSION} run of ${binary} with arguments ${JSON.stringify(argv)}: ${ran.length} of ` +
      `${entries.length} functions ran (${result.exit})`,
    limitations: [
      "only the paths this input took; functions Frida could not hook (too short) are not seen",
      "argument registers are classified by value: a pointer-sized integer that lands in mapped memory reads as a pointer",
    ],
    created_at: now.toISOString(),
  });
  const hypotheses: string[] = [];
  store.transaction(() => {
    for (const [address, t] of ran) {
      const fn = byAddress.get(BigInt(address));
      if (fn === undefined) continue;
      const value = observedSignature(t);
      const id = `hyp_${createHash("sha256").update(`${fn.id}\nsignature\ntrace\n${run}`).digest("hex").slice(0, 32)}`;
      const hypothesis: Hypothesis = {
        schema_version: 1,
        id,
        node: fn.id,
        kind: "signature",
        value,
        confidence: "observed",
        evidence: [evidence],
        author: { agent: "tracer/frida" },
      };
      if (store.getHypothesis(id) === undefined) store.proposeHypothesis(hypothesis);
      hypotheses.push(id);
    }
  });
  return {
    binary,
    evidence,
    exit: result.exit,
    ran: ran.length,
    hooked: entries.filter(([, t]) => t.error === undefined).length,
    unhooked: entries.filter(([, t]) => t.error !== undefined).length,
    hypotheses,
  };
}
