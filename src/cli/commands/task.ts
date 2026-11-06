// atlas get task rewrite <fn_id|0xaddress>, atlas list tasks rewrite [--binary <bin_>]
import type { GraphStore, TaskClaims } from "../../graph/index.js";
import { resolveFunction } from "../../orchestrator/function-context.js";
import { rewriteQueue } from "../../orchestrator/rewrite-queue.js";
import { rewriteTask } from "../../orchestrator/rewrite-task.js";
import { CliError, type Output } from "../output.js";

export async function runGetTask(
  store: GraphStore,
  claims: TaskClaims,
  args: string[],
  binary: string | undefined,
): Promise<Output> {
  const [kind, ref, ...extra] = args;
  if (kind !== "rewrite" || ref === undefined || extra.length > 0) {
    throw new CliError("usage", "usage: atlas get task rewrite <fn_id|0xaddress>");
  }
  const task = await rewriteTask(store, resolveFunction(store, ref, binary));
  const notes = claims.notes(task.function.id);
  const lines = [
    `${task.function.id} at ${task.function.address ?? "?"} (${task.function.size ?? "?"} bytes), ${task.status}`,
    `toolchain: ${task.toolchain === undefined ? "not detected (atlas detect toolchain)" : `${task.toolchain.cc} ${task.toolchain.flags.join(" ")}`}`,
    "original:",
    ...task.original.map((i) => `  ${i.address}: ${i.text}`),
    `attempts (${task.attempts.length}):`,
    ...task.attempts.map(
      (a) => `  ${a.hypothesis} by ${a.author}: ${a.confidence}; ${a.verification?.details ?? "not checked"}`,
    ),
    ...(task.closest === undefined
      ? []
      : [
          `closest attempt ${task.closest.hypothesis} compiled to:`,
          ...task.closest.compiled.map((i) => `  ${i.address}: ${i.text}`),
        ]),
    `callees: ${task.callees.map((c) => c.prototype ?? c.label ?? c.id).join("; ") || "none"}`,
    `strings: ${task.strings.map((s) => JSON.stringify(s.value)).join(", ") || "none"}`,
    ...notes.map((n) => `note from ${n.agent}: ${n.note}`),
    task.answer,
  ];
  return { data: { ...task, notes }, text: lines.join("\n") };
}

export function runListTasks(store: GraphStore, args: string[], binary: string | undefined): Output {
  const [kind, ...extra] = args;
  if (kind !== "rewrite" || extra.length > 0)
    throw new CliError("usage", "usage: atlas list tasks rewrite [--binary <bin_>]");
  const binaries = store.nodesOfKind("binary").filter((b) => binary === undefined || b.id === binary);
  if (binaries.length !== 1) {
    throw new CliError(
      "usage",
      binaries.length === 0 ? `no binary ${binary ?? ""}` : "the graph holds several binaries; name one with --binary",
    );
  }
  const id = (binaries[0] as { id: string }).id;
  const queue = rewriteQueue(store, id);
  return {
    data: { binary: id, open: queue.length, tasks: queue },
    text: [
      `${queue.length} functions to rewrite in ${id}, callees first:`,
      ...queue.map((q) => `  ${q.id}  ${q.label ?? ""}`),
    ].join("\n"),
  };
}
