// atlas list callers|callees <fn_id|0xaddress>, atlas list functions
import type { GraphStore } from "../../graph/index.js";
import { functionContext, resolveFunction } from "../../orchestrator/function-context.js";
import { CliError, type Output } from "../output.js";
import { describeNode } from "./get-function.js";

export function runList(store: GraphStore, args: string[], binary: string | undefined): Output {
  const [what, ref, ...extra] = args;
  if (what === "functions" && ref === undefined) {
    const functions = store.nodesOfKind("function").filter((n) => binary === undefined || n.binary === binary);
    return { data: { functions }, text: functions.map(describeNode).join("\n") };
  }
  if ((what === "callers" || what === "callees") && ref !== undefined && extra.length === 0) {
    const context = functionContext(store, resolveFunction(store, ref, binary));
    const nodes = what === "callers" ? context.callers : context.callees;
    return { data: { function: context.function.id, [what]: nodes }, text: nodes.map(describeNode).join("\n") };
  }
  throw new CliError("usage", "usage: atlas list callers|callees <fn_id|0xaddress> | atlas list functions");
}
