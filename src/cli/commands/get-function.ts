// atlas get function <fn_id|0xaddress>
import type { GraphNode, GraphStore } from "../../graph/index.js";
import { functionContext, resolveFunction } from "../../orchestrator/function-context.js";
import { CliError, type Output } from "../output.js";

export function describeNode(n: GraphNode): string {
  return `${n.id}  ${n.address ?? ""}  ${n.label ?? ""}`.trimEnd();
}

export function runGetFunction(store: GraphStore, args: string[], binary: string | undefined): Output {
  const [what, ref, ...extra] = args;
  if (what !== "function" || ref === undefined || extra.length > 0) {
    throw new CliError("usage", "usage: atlas get function <fn_id|0xaddress>");
  }
  const context = functionContext(store, resolveFunction(store, ref, binary));
  const f = context.function;
  const lines = [
    `${f.id} at ${f.address ?? "?"}, ${f.size ?? "?"} bytes, label ${f.label ?? "-"}`,
    `callers (${context.callers.length}):`,
    ...context.callers.map((n) => `  ${describeNode(n)}`),
    `callees (${context.callees.length}):`,
    ...context.callees.map((n) => `  ${describeNode(n)}`),
    `strings (${context.strings.length}):`,
    ...context.strings.map((n) => `  ${n.address ?? ""}  ${JSON.stringify(n.label ?? "")}`),
    `hypotheses (${context.hypotheses.length}):`,
    ...context.hypotheses.map((h) => `  ${h.kind} = ${JSON.stringify(h.value)} (${h.confidence})`),
  ];
  return { data: context, text: lines.join("\n") };
}
