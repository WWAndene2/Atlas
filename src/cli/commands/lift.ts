// atlas lift <file> --out <dir> [--arch <a> --base <0x..>]: every function of a loaded binary translated to C.
import { existsSync } from "node:fs";
import type { GraphStore } from "../../graph/index.js";
import { fileSha256 } from "../../orchestrator/file-hash.js";
import { linkBase, linkBinary } from "../../orchestrator/link-binary.js";
import { liftBinary } from "../../orchestrator/lift-binary.js";
import { binaryId } from "../../orchestrator/load-binary.js";
import { resolveTarget } from "../../orchestrator/resolve-target.js";
import type { EngineInput } from "../../tools/engine-analysis.js";
import { AngrUnavailableError } from "../../tools/angr/index.js";
import { CliError, type Output } from "../output.js";

export async function runLift(
  store: GraphStore,
  args: string[],
  out: string | undefined,
  raw: EngineInput["raw"],
  link = false,
): Promise<Output> {
  const [path, ...extra] = args;
  if (path === undefined || out === undefined || extra.length > 0) {
    throw new CliError("usage", "usage: atlas lift <file> --out <dir> [--link] [--arch <a> --base <0x..>]");
  }
  if (!existsSync(path)) throw new CliError("not_found", `no file ${path}`);
  const target = await resolveTarget(path, raw);
  try {
    const results: (Awaited<ReturnType<typeof liftBinary>> & {
      label: string;
      linked?: Awaited<ReturnType<typeof linkBinary>>;
    })[] = [];
    for (const b of target.binaries) {
      const binary = binaryId(await fileSha256(b.input.path));
      if (store.getNode(binary) === undefined)
        throw new CliError("not_found", `${b.label} is not loaded; atlas load it first`);
      // Jump tables are resolved from the file when angr can load it (a raw image it cannot).
      const dir = target.binaries.length === 1 ? out : `${out}/${b.label.replace(/[^\w.-]+/g, "_")}`;
      const base = link ? linkBase(b.input.path) : 0;
      const lifted = await liftBinary(store, binary, dir, b.input.raw === undefined ? b.input.path : undefined, base);
      // With --link, the translations and the verified rewrites become one program (x86-64 on x86-64 for now).
      const linked = link ? await linkBinary(store, binary, b.input.path, dir, lifted.addresses) : undefined;
      results.push({ label: b.label, ...lifted, ...(linked !== undefined ? { linked } : {}) });
    }
    const text = results
      .map((r) => {
        const reasons = Object.entries(r.unsupported)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([k, n]) => `${n} ${k}`)
          .join("; ");
        const linked =
          r.linked === undefined
            ? ""
            : `\n  linked: ${r.linked.executable}, ${r.linked.rewrites} verified rewrites in place of their translations` +
              ` (${r.linked.rewrites_skipped.length} kept as translations)`;
        return `${r.label}: ${r.translated} of ${r.functions} functions translated to C in ${r.files[0]?.replace(/\/[^/]+$/, "")}${reasons ? ` (not: ${reasons})` : ""}${linked}`;
      })
      .join("\n");
    return { data: { binaries: results }, text };
  } catch (error) {
    if (error instanceof AngrUnavailableError) throw new CliError("no_engine", error.message);
    throw error;
  } finally {
    await target.dispose();
  }
}
