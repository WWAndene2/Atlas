// atlas cluster systems [--binary <bin_>], atlas get system <sys_>, atlas propose summary <sys_> <text> --name <n>
import type { GraphStore } from "../../graph/index.js";
import { clusterSystems, proposeSummary, systemContext } from "../../orchestrator/cluster-systems.js";
import { NotFoundError } from "../../orchestrator/function-context.js";
import { CliError, type Output } from "../output.js";

function onlyBinary(store: GraphStore, binary: string | undefined): string {
  const binaries = store.nodesOfKind("binary").filter((b) => binary === undefined || b.id === binary);
  if (binaries.length !== 1) {
    throw new CliError(
      "usage",
      binaries.length === 0 ? `no binary ${binary ?? ""}` : "several binaries: name one with --binary",
    );
  }
  return (binaries[0] as { id: string }).id;
}

export function runClusterSystems(store: GraphStore, args: string[], binary: string | undefined): Output {
  if (args[0] !== "systems" || args.length > 1)
    throw new CliError("usage", "usage: atlas cluster systems [--binary <bin_>]");
  const o = clusterSystems(store, onlyBinary(store, binary));
  return {
    data: o,
    text: [
      `${o.systems.length} systems`,
      ...o.systems.map((s) => `${s.id}  ${s.first}-${s.last}  ${s.functions} functions`),
    ].join("\n"),
  };
}

export function runGetSystem(store: GraphStore, args: string[]): Output {
  const [id, ...extra] = args;
  if (id === undefined || extra.length > 0) throw new CliError("usage", "usage: atlas get system <sys_id>");
  try {
    const c = systemContext(store, id);
    return {
      data: c,
      text: [
        `${c.system.id}: ${c.functions.length} functions, ${c.strings.length} strings, ${c.calls_out.length} calls out`,
        ...c.summaries.map((h) => `summary (${h.confidence}): ${JSON.stringify(h.value)}`),
        ...c.functions.map((f) => `  ${f.address} ${f.name ?? ""}`),
        ...c.strings.slice(0, 30).map((s) => `  string ${JSON.stringify(s)}`),
      ].join("\n"),
    };
  } catch (error) {
    if (error instanceof NotFoundError) throw new CliError("not_found", error.message);
    throw error;
  }
}

export function runProposeSummary(
  store: GraphStore,
  args: string[],
  name: string | undefined,
  agent: string | undefined,
): Output {
  const [, id, text, ...extra] = args;
  if (id === undefined || text === undefined || name === undefined || extra.length > 0) {
    throw new CliError(
      "usage",
      'usage: atlas propose summary <sys_id> "<what it does>" --name <system name> [--agent <name>]',
    );
  }
  try {
    const hypothesis = proposeSummary(store, id, name, text, agent ?? "agent");
    return { data: { hypothesis }, text: `${hypothesis.id}: ${name}` };
  } catch (error) {
    if (error instanceof NotFoundError) throw new CliError("not_found", error.message);
    throw error;
  }
}
