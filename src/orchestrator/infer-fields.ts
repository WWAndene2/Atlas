// The typer's first step (M4): for each function, the fields its pointer arguments point to, from the accesses angr
// sees through them (src/tools/angr/fields.py). Recorded as a signature hypothesis (inferred, author typer/angr):
// per argument register, the offsets and widths read or written. Then checked against execution where a trace
// exists (atlas trace): an argument with fields that the trace only ever saw holding integers contradicts it (fail);
// one the trace saw holding pointers confirms it (pass, observed). x86-64 ELF for now.
import { createHash } from "node:crypto";
import { openSync, readSync, closeSync } from "node:fs";
import type { GraphNode, GraphStore, Hypothesis } from "../graph/index.js";
import { functionFields, locateAngr, type FieldAccess } from "../tools/angr/index.js";
import { forEachConcurrently } from "./parallel.js";

const REGISTERS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
/** Functions per angr process: each process loads the binary once. */
const BATCH = 25;

export interface FieldsArgument {
  register: string;
  fields: { offset: number; size: number; access: "r" | "w" | "rw" }[];
}

export interface InferOutcome {
  functions: number;
  withFields: number;
  complete: number;
  checked: { pass: number; fail: number };
  /** Functions whose angr process failed (crash, out of memory): left without fields. */
  failed: number;
}

function elfType(path: string): number {
  const fd = openSync(path, "r");
  try {
    const header = Buffer.alloc(18);
    readSync(fd, header, 0, 18, 0);
    if (header.readUInt32BE(0) !== 0x7f454c46) throw new Error("the fields inference reads ELF programs only for now");
    return header.readUInt16LE(16);
  } finally {
    closeSync(fd);
  }
}

function asArguments(args: Record<string, FieldAccess[]>): FieldsArgument[] {
  return Object.entries(args)
    .map(([i, accesses]) => ({
      register: REGISTERS[Number(i)] as string,
      fields: accesses
        .filter((a) => a.size > 0)
        .map((a) => ({
          offset: a.offset,
          size: a.size,
          access: (a.read && a.write ? "rw" : a.write ? "w" : "r") as "r" | "w" | "rw",
        })),
    }))
    .filter((a) => a.fields.length > 0);
}

/** pass when every argument with fields was seen holding pointers, fail when one was only ever seen as integers. */
function againstTrace(store: GraphStore, fn: GraphNode, args: FieldsArgument[]): "pass" | "fail" | undefined {
  const traces = store
    .hypothesesFor(fn.id, "signature")
    .filter((h) => h.author.agent === "tracer/frida")
    .map((h) => h.value as { arguments: { register: string; seen: string }[] });
  if (traces.length === 0) return undefined;
  const seen = (register: string) => traces.map((t) => t.arguments.find((a) => a.register === register)?.seen);
  if (args.some((a) => seen(a.register).every((s) => s === "integer"))) return "fail";
  if (args.every((a) => seen(a.register).some((s) => s === "pointer"))) return "pass";
  return undefined;
}

export async function inferFields(
  store: GraphStore,
  binary: string,
  path: string,
  options: { only?: string[]; seconds?: number } = {},
): Promise<InferOutcome> {
  if (store.getNode(binary)?.architecture !== "x86_64") throw new Error("the fields inference covers x86-64 for now");
  const positionIndependent = elfType(path) === 3;
  const functions = store
    .nodesOfKind("function")
    .filter(
      (f) =>
        f.binary === binary &&
        f.address !== undefined &&
        f.thunk !== true &&
        f.generated === undefined &&
        (options.only === undefined || options.only.includes(f.id)),
    );
  const batches: GraphNode[][] = [];
  for (let i = 0; i < functions.length; i += BATCH) batches.push(functions.slice(i, i + BATCH));
  const python = locateAngr();
  const outcome: InferOutcome = {
    functions: functions.length,
    withFields: 0,
    complete: 0,
    checked: { pass: 0, fail: 0 },
    failed: 0,
  };
  await forEachConcurrently(batches, async (batch) => {
    let found;
    try {
      found = await functionFields(
        python,
        path,
        batch.map((f) => Number(BigInt(f.address as string))),
        { positionIndependent, ...(options.seconds !== undefined ? { seconds: options.seconds } : {}) },
      );
    } catch {
      // One batch lost does not lose the others: its functions are counted and left without fields.
      outcome.failed += batch.length;
      return;
    }
    store.transaction(() => {
      for (const fn of batch) {
        const r = found[`0x${BigInt(fn.address as string).toString(16)}`];
        if (r === undefined) continue;
        if (r.complete) outcome.complete++;
        const args = asArguments(r.args);
        if (args.length === 0) continue;
        outcome.withFields++;
        const value = { arguments: args, complete: r.complete };
        const id = `hyp_${createHash("sha256")
          .update(`${fn.id}\nsignature\nfields\n${JSON.stringify(value)}`)
          .digest("hex")
          .slice(0, 32)}`;
        if (store.getHypothesis(id) === undefined) {
          const hypothesis: Hypothesis = {
            schema_version: 1,
            id,
            node: fn.id,
            kind: "signature",
            value,
            confidence: "inferred",
            evidence: [fn.id],
            author: { agent: "typer/angr" },
          };
          store.proposeHypothesis(hypothesis);
        }
        const check = againstTrace(store, fn, args);
        if (check !== undefined) {
          outcome.checked[check]++;
          store.recordVerification(id, {
            confidence: check === "pass" ? "observed" : "rejected",
            verification: {
              check: "trace_types",
              result: check,
              details:
                check === "pass"
                  ? "every argument with fields held pointers when traced"
                  : "an argument with fields only ever held integers when traced",
            },
          });
        }
      }
    });
  });
  return outcome;
}
