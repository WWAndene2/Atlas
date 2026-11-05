// The whole job on one target, by one command: open the file, load each binary it holds with every engine,
// decompile, detect the toolchain, recognise library code, verify every rewrite, and report what is verified, what
// is library code and what is still open. Agents working the open tasks in parallel (roadmap M6) come between
// verification and the report; until then the report hands the open tasks over, callees first.
import type { GraphStore, Hypothesis } from "../graph/index.js";
import type { EngineInput } from "../tools/engine-analysis.js";
import { verifyRewrite } from "../verify/recompile/verify-rewrite.js";
import { binaryFacts } from "./binary-facts.js";
import { decompileFunctions } from "./decompile-functions.js";
import { binaryToolchain, detectToolchain, type ToolchainValue } from "./detect-toolchain.js";
import { loadTarget } from "./load-target.js";
import { matchLibraries } from "./match-libraries.js";
import { forEachConcurrently } from "./parallel.js";
import { resolveTarget } from "./resolve-target.js";
import { rewriteQueue, verifiedFunctions } from "./rewrite-queue.js";
import { toolchainLibraries } from "./toolchain-libraries.js";

export interface BinaryReport {
  label: string;
  binary?: string;
  architecture?: string;
  functions: number;
  stubs: number;
  library: number;
  verified: number;
  open: number;
  toolchain?: ToolchainValue;
  /** The first open functions, callees first: where agents start. */
  next: string[];
  /** Steps that could not run, and why. The run goes on without them. */
  problems: string[];
  seconds: Record<string, number>;
}

export interface RunReport {
  target: string;
  goal: string;
  binaries: BinaryReport[];
  unreadable: { label: string; reason: string }[];
}

async function timed<T>(seconds: Record<string, number>, step: string, work: () => Promise<T>): Promise<T> {
  const start = Date.now();
  try {
    return await work();
  } finally {
    seconds[step] = Math.round((Date.now() - start) / 100) / 10;
  }
}

async function runBinary(store: GraphStore, input: EngineInput, label: string): Promise<BinaryReport> {
  const report: BinaryReport = {
    label,
    functions: 0,
    stubs: 0,
    library: 0,
    verified: 0,
    open: 0,
    next: [],
    problems: [],
    seconds: {},
  };
  const outcomes = await timed(report.seconds, "load", () => loadTarget(store, input, undefined, label));
  const binary = outcomes.find((o) => o.loaded !== undefined)?.loaded?.binary;
  for (const o of outcomes) if (o.skipped !== undefined) report.problems.push(`${o.engine} skipped: ${o.skipped}`);
  if (binary === undefined) return report;
  report.binary = binary;
  const node = store.getNode(binary);
  if (node?.architecture !== undefined) report.architecture = node.architecture;

  await timed(report.seconds, "decompile", () => decompileFunctions(store, input));
  try {
    await timed(report.seconds, "detect", () => detectToolchain(store, binary, binaryFacts(input)));
  } catch (error) {
    report.problems.push(`toolchain not detected: ${(error as Error).message}`);
  }
  const toolchain = binaryToolchain(store, binary);
  if (toolchain !== undefined) {
    report.toolchain = toolchain;
    const libraries = toolchainLibraries(toolchain);
    if (libraries.length > 0) await timed(report.seconds, "libraries", () => matchLibraries(store, binary, libraries));
    // Every rewrite of this binary not yet checked, with the detected toolchain.
    const pending = (store.allRecords("hypotheses") as Hypothesis[]).filter(
      (h) => h.kind === "rewrite" && h.verification === undefined && store.getNode(h.node)?.binary === binary,
    );
    await timed(report.seconds, "verify", () =>
      forEachConcurrently(pending, async (h) => {
        await verifyRewrite(store, h.id, { cc: toolchain.cc, flags: toolchain.flags });
      }),
    );
  } else {
    report.problems.push(
      "no toolchain: rewrites not verified (install the target's compiler and run atlas detect toolchain)",
    );
  }

  const functions = store.nodesOfKind("function").filter((n) => n.binary === binary);
  report.functions = functions.length;
  report.stubs = functions.filter((n) => n.thunk === true).length;
  report.library = functions.filter((n) =>
    store.hypothesesFor(n.id, "match").some((h) => h.confidence !== "rejected"),
  ).length;
  report.verified = verifiedFunctions(store, binary).size;
  const queue = rewriteQueue(store, binary);
  report.open = queue.length;
  report.next = queue.slice(0, 10).map((q) => q.id);
  return report;
}

export async function runTarget(
  store: GraphStore,
  path: string,
  goal: string,
  raw?: EngineInput["raw"],
): Promise<RunReport> {
  const target = await resolveTarget(path, raw);
  const report: RunReport = { target: path, goal, binaries: [], unreadable: target.unreadable };
  try {
    for (const b of target.binaries) {
      try {
        report.binaries.push(await runBinary(store, b.input, b.label));
      } catch (error) {
        report.binaries.push({
          label: b.label,
          functions: 0,
          stubs: 0,
          library: 0,
          verified: 0,
          open: 0,
          next: [],
          problems: [(error as Error).message],
          seconds: {},
        });
      }
    }
  } finally {
    await target.dispose();
  }
  return report;
}

/** The report as Markdown, for the operator to read. */
export function reportMarkdown(report: RunReport): string {
  const lines = [`# Atlas report: ${report.target}`, "", `Goal: ${report.goal}`, ""];
  for (const b of report.binaries) {
    const toRewrite = b.functions - b.stubs - b.library;
    lines.push(
      `## ${b.label}`,
      "",
      `- Binary: ${b.binary ?? "not loaded"}${b.architecture !== undefined ? `, ${b.architecture}` : ""}`,
      `- Toolchain: ${b.toolchain === undefined ? "unknown" : `${b.toolchain.cc} ${b.toolchain.flags.join(" ")} (${b.toolchain.verified} of ${b.toolchain.sample} probed functions reproduced${b.toolchain.ties.length > 0 ? `; tied with ${b.toolchain.ties.map((t) => t.join(" ")).join(", ")}` : ""})`}`,
      `- Functions: ${b.functions}, of which ${b.stubs} import stubs and ${b.library} library code (linked, not rewritten)`,
      `- Rewritten and verified byte for byte: ${b.verified} of ${toRewrite} (${toRewrite > 0 ? ((100 * b.verified) / toRewrite).toFixed(1) : "0"}%)`,
      `- Open: ${b.open}. Next, callees first: ${b.next.join(", ") || "none"}`,
      `  (for each: \`atlas get task rewrite <fn> --json\`, then \`atlas propose rewrite\` and \`atlas verify\`)`,
      `- Time: ${Object.entries(b.seconds)
        .map(([k, v]) => `${k} ${v} s`)
        .join(", ")}`,
      ...b.problems.map((p) => `- Problem: ${p}`),
      "",
    );
  }
  for (const u of report.unreadable) lines.push(`- Unreadable: ${u.label}: ${u.reason}`);
  return lines.join("\n");
}
