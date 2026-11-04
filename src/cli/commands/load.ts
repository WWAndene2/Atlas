// atlas load <binary> [--arch <architecture> --base <0xaddress>]
import { existsSync } from "node:fs";
import type { GraphStore } from "../../graph/index.js";
import { loadTarget } from "../../orchestrator/load-target.js";
import { resolveTarget } from "../../orchestrator/resolve-target.js";
import { ARCHITECTURES, type Architecture, type EngineInput } from "../../tools/engine-analysis.js";
import { CliError, type Output } from "../output.js";

function input(path: string, arch: string | undefined, base: string | undefined): EngineInput {
  if (arch === undefined && base === undefined) return { path };
  if (arch === undefined || base === undefined) {
    throw new CliError("usage", "--arch and --base go together: a raw image needs both its CPU and its load address");
  }
  if (!(ARCHITECTURES as readonly string[]).includes(arch)) {
    throw new CliError("usage", `unknown architecture ${arch}; known: ${ARCHITECTURES.join(", ")}`);
  }
  if (!/^0x[0-9a-fA-F]+$/.test(base)) throw new CliError("usage", `--base ${base} is not a hex address (0x...)`);
  return { path, raw: { architecture: arch as Architecture, base: `0x${BigInt(base).toString(16)}` } };
}

export async function runLoad(
  store: GraphStore,
  args: string[],
  arch: string | undefined,
  base: string | undefined,
): Promise<Output> {
  const [path, ...extra] = args;
  if (path === undefined || extra.length > 0) {
    throw new CliError("usage", "usage: atlas load <binary> [--arch <architecture> --base <0xaddress>]");
  }
  const { raw } = input(path, arch, base);
  if (!existsSync(path)) throw new CliError("not_found", `no file ${path}`);
  const target = await resolveTarget(path, raw);
  let engines;
  try {
    engines = await loadTarget(store, target.input, undefined, target.label);
  } finally {
    await target.dispose();
  }
  const text = engines
    .map((e) =>
      e.loaded !== undefined
        ? `${e.engine}: ${e.loaded.functions} functions, ${e.loaded.calls} calls, ${e.loaded.strings} strings into ${e.loaded.binary}`
        : `${e.engine}: skipped (${e.skipped})`,
    )
    .join("\n");
  const c = target.container;
  const opened =
    c === undefined
      ? ""
      : `3DS ${c.container.toUpperCase()} "${c.title}" (program ${c.programId}): code at ${c.base}, ` +
        `text ${c.text.size} bytes, rodata ${c.rodata.size}, data ${c.data.size}\n`;
  return { data: { container: c, engines }, text: opened + text };
}
