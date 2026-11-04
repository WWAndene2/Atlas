// atlas load <binary> [--arch <architecture> --base <0xaddress>]
import { existsSync } from "node:fs";
import type { GraphStore } from "../../graph/index.js";
import { loadTarget, type EngineOutcome } from "../../orchestrator/load-target.js";
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
  const binaries: { label: string; engines?: EngineOutcome[]; error?: string }[] = target.unreadable.map((u) => ({
    label: u.label,
    error: u.reason,
  }));
  try {
    if (target.binaries.length === 0) {
      const why = binaries.length > 0 ? `: ${binaries.map((b) => `${b.label}: ${b.error}`).join("; ")}` : "";
      throw new CliError("not_found", `${path} holds no executable Atlas could read${why}`);
    }
    for (const binary of target.binaries) {
      try {
        binaries.push({ label: binary.label, engines: await loadTarget(store, binary.input, undefined, binary.label) });
      } catch (error) {
        // One binary of a package failing (an engine cannot read it) must not lose the others.
        if (target.binaries.length === 1 && binaries.length === 0) throw error;
        binaries.push({ label: binary.label, error: (error as Error).message });
      }
    }
  } finally {
    await target.dispose();
  }
  const lines: string[] = [];
  const c = target.container;
  if (c?.format === "3ds") {
    lines.push(
      `3DS ${c.code.container.toUpperCase()} "${c.code.title}" (program ${c.code.programId}): code at ${c.code.base}, ` +
        `text ${c.code.text.size} bytes, rodata ${c.code.rodata.size}, data ${c.code.data.size}`,
    );
  }
  if (c?.format === "zip") lines.push(`archive: ${target.binaries.length} executables among ${c.members} members`);
  for (const b of binaries) {
    if (binaries.length > 1) lines.push(`${b.label}:`);
    if (b.error !== undefined) lines.push(`  failed: ${b.error}`);
    for (const e of b.engines ?? []) {
      lines.push(
        e.loaded !== undefined
          ? `${e.engine}: ${e.loaded.functions} functions, ${e.loaded.calls} calls, ${e.loaded.strings} strings into ${e.loaded.binary}`
          : `${e.engine}: skipped (${e.skipped})`,
      );
    }
  }
  return { data: { container: c, binaries }, text: lines.join("\n") };
}
