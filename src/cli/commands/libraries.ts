// atlas match libraries [--library <file.a|file.o>]... [--binary <bin_>]
import type { GraphStore } from "../../graph/index.js";
import { binaryToolchain } from "../../orchestrator/detect-toolchain.js";
import { matchLibraries } from "../../orchestrator/match-libraries.js";
import { toolchainLibraries } from "../../orchestrator/toolchain-libraries.js";
import { CliError, type Output } from "../output.js";

export async function runMatchLibraries(
  store: GraphStore,
  args: string[],
  libraries: string[],
  binary: string | undefined,
): Promise<Output> {
  const [what, ...extra] = args;
  if (what !== "libraries" || extra.length > 0) {
    throw new CliError("usage", "usage: atlas match libraries [--library <file.a>]... [--binary <bin_>]");
  }
  const binaries = store.nodesOfKind("binary").filter((b) => binary === undefined || b.id === binary);
  if (binaries.length !== 1) {
    throw new CliError(
      "usage",
      binaries.length === 0 ? `no binary ${binary ?? ""}` : "several binaries: name one with --binary",
    );
  }
  const id = (binaries[0] as { id: string }).id;
  const toolchain = binaryToolchain(store, id);
  const paths = [...libraries, ...(toolchain === undefined ? [] : toolchainLibraries(toolchain))];
  if (paths.length === 0) {
    throw new CliError(
      "usage",
      "no library to match: give --library, or run atlas detect toolchain for the toolchain's own",
    );
  }
  const outcome = await matchLibraries(store, id, paths);
  return {
    data: outcome,
    text:
      `${outcome.matched} functions matched (${outcome.named} named) against ` +
      outcome.libraries.map((l) => `${l.path} (${l.functions} functions)`).join(", "),
  };
}
