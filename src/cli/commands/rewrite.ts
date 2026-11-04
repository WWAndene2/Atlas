// atlas decompile <file> [--arch --base] [--function <fn|0x>...]
// atlas propose rewrite <fn_id|0xaddress> --source <file.c> --name <function> [--prelude ghidra]
// atlas verify <hyp_id> --cc <compiler> [--cflags "<flags>"]
import { existsSync, readFileSync } from "node:fs";
import type { GraphStore, Hypothesis } from "../../graph/index.js";
import { binaryFacts } from "../../orchestrator/binary-facts.js";
import { decompileFunctions } from "../../orchestrator/decompile-functions.js";
import { binaryToolchain, detectToolchain } from "../../orchestrator/detect-toolchain.js";
import { fileSha256 } from "../../orchestrator/file-hash.js";
import { binaryId } from "../../orchestrator/load-binary.js";
import { resolveFunction } from "../../orchestrator/function-context.js";
import { proposeRewrite } from "../../orchestrator/propose-rewrite.js";
import { resolveTarget } from "../../orchestrator/resolve-target.js";
import type { EngineInput } from "../../tools/engine-analysis.js";
import { verifyRewrite } from "../../verify/recompile/verify-rewrite.js";
import { CliError, type Output } from "../output.js";

export async function runDecompile(
  store: GraphStore,
  args: string[],
  raw: EngineInput["raw"],
  functions: string[],
  binary: string | undefined,
): Promise<Output> {
  const [path, ...extra] = args;
  if (path === undefined || extra.length > 0) {
    throw new CliError("usage", "usage: atlas decompile <file> [--arch <a> --base <0x..>] [--function <fn|0x>...]");
  }
  if (!existsSync(path)) throw new CliError("not_found", `no file ${path}`);
  const addresses =
    functions.length === 0 ? undefined : functions.map((f) => resolveFunction(store, f, binary).address ?? "");
  const target = await resolveTarget(path, raw);
  const results = [];
  try {
    for (const b of target.binaries)
      results.push({ label: b.label, ...(await decompileFunctions(store, b.input, addresses)) });
  } finally {
    await target.dispose();
  }
  const text = results
    .map((r) => `${r.label}: ${r.proposed.length} rewrites proposed, ${r.skipped.length} skipped`)
    .join("\n");
  return {
    data: {
      binaries: results.map((r) => ({ label: r.label, proposed: r.proposed.map((h) => h.id), skipped: r.skipped })),
    },
    text,
  };
}

export function runProposeRewrite(
  store: GraphStore,
  args: string[],
  options: { source?: string; name?: string; prelude?: string; binary?: string; last?: string; lastName?: string },
): Output {
  const [what, ref, ...extra] = args;
  if (what !== "rewrite" || ref === undefined || extra.length > 0 || !options.source || !options.name) {
    throw new CliError(
      "usage",
      "usage: atlas propose rewrite <fn_id|0xaddress> --source <file.c> --name <function> [--prelude ghidra]",
    );
  }
  if (options.prelude !== undefined && options.prelude !== "ghidra")
    throw new CliError("usage", "--prelude takes only ghidra");
  if (!existsSync(options.source)) throw new CliError("not_found", `no file ${options.source}`);
  const fn = resolveFunction(store, ref, options.binary);
  if ((options.last === undefined) !== (options.lastName === undefined)) {
    throw new CliError(
      "usage",
      "--last and --last-name go together: the run's last function and its name in the source",
    );
  }
  const last =
    options.last !== undefined && options.lastName !== undefined
      ? { node: resolveFunction(store, options.last, options.binary).id, name: options.lastName }
      : undefined;
  const hypothesis = proposeRewrite(
    store,
    fn.id,
    {
      language: "c",
      source: readFileSync(options.source, "utf8"),
      name: options.name,
      ...(options.prelude === "ghidra" ? { prelude: "ghidra" as const } : {}),
      ...(last !== undefined ? { last } : {}),
    },
    "agent",
  );
  return { data: { hypothesis }, text: `${hypothesis.id} proposed for ${fn.id}` };
}

export async function runVerify(
  store: GraphStore,
  args: string[],
  options: { cc?: string; cflags?: string },
): Promise<Output> {
  const [id, ...extra] = args;
  if (id === undefined || extra.length > 0) {
    throw new CliError(
      "usage",
      'usage: atlas verify <hyp_id|all> [--cc <compiler> --cflags="<flags>"] (with =: the flags start with a dash; without --cc, the toolchain detected for the binary)',
    );
  }
  const flags = (options.cflags ?? "").split(/\s+/).filter((f) => f !== "");
  // Without --cc, each rewrite is checked with the toolchain detected for its binary (atlas detect toolchain).
  const given = options.cc !== undefined ? { cc: options.cc, flags } : undefined;
  const toolchainFor = (h: Hypothesis): { cc: string; flags: string[] } => {
    if (given !== undefined) return given;
    const binary = store.getNode(h.node)?.binary;
    const detected = binary === undefined ? undefined : binaryToolchain(store, binary);
    if (detected === undefined) {
      throw new CliError(
        "usage",
        `no toolchain for ${binary ?? h.node}: give --cc and --cflags, or run atlas detect toolchain`,
      );
    }
    return { cc: detected.cc, flags: detected.flags };
  };
  if (id === "all") {
    // Every rewrite not checked yet, in one process: a whole binary costs one start, not one per function.
    const pending = (store.allRecords("hypotheses") as Hypothesis[]).filter(
      (h) => h.kind === "rewrite" && h.verification === undefined,
    );
    const counts: Record<string, number> = {};
    for (const h of pending) {
      const { check } = await verifyRewrite(store, h.id, toolchainFor(h));
      const key = check.result === "pass" ? "verified" : check.reason;
      counts[key] = (counts[key] ?? 0) + 1;
    }
    const text = `${pending.length} rewrites checked: ${Object.entries(counts)
      .map(([k, n]) => `${n} ${k}`)
      .join(", ")}`;
    return { data: { checked: pending.length, counts }, text };
  }
  const target = store.getHypothesis(id);
  if (target === undefined) throw new CliError("not_found", `no hypothesis ${id}`);
  const { hypothesis, check } = await verifyRewrite(store, id, toolchainFor(target));
  return {
    data: { hypothesis, check },
    text: `${hypothesis.id}: ${check.result} (${hypothesis.verification?.details ?? ""}) -> ${hypothesis.confidence}`,
  };
}

export async function runDetectToolchain(store: GraphStore, args: string[], raw: EngineInput["raw"]): Promise<Output> {
  const [what, path, ...extra] = args;
  if (what !== "toolchain" || path === undefined || extra.length > 0) {
    throw new CliError("usage", "usage: atlas detect toolchain <file> [--arch <a> --base <0x..>]");
  }
  if (!existsSync(path)) throw new CliError("not_found", `no file ${path}`);
  const target = await resolveTarget(path, raw);
  const results = [];
  try {
    for (const b of target.binaries) {
      const binary = binaryId(await fileSha256(b.input.path));
      if (store.getNode(binary) === undefined)
        throw new CliError("not_found", `${b.label} is not loaded; atlas load it first`);
      const facts = binaryFacts(b.input);
      const { value, hypothesis, tried } = await detectToolchain(store, binary, facts);
      results.push({ label: b.label, binary, facts, toolchain: value, hypothesis: hypothesis?.id, tried });
    }
  } finally {
    await target.dispose();
  }
  const text = results
    .map((r) =>
      r.toolchain === undefined
        ? `${r.label}: no candidate reproduced any function (tried ${r.tried.length}); the toolchain stays unknown`
        : `${r.label}: ${r.toolchain.cc} ${r.toolchain.flags.join(" ")} (${r.toolchain.verified} of ${r.toolchain.sample} ` +
          `functions reproduced${r.toolchain.ties.length > 0 ? `; tied: ${r.toolchain.ties.map((t) => t.join(" ")).join(" | ")}` : ""})` +
          `${r.facts.clues.length > 0 ? `; clues: ${r.facts.clues.join(", ")}` : ""}`,
    )
    .join("\n");
  return { data: { binaries: results }, text };
}
