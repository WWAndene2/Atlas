// Finds how a binary was compiled, which the recompile check needs and a real target does not state. Two sources:
// the clues compilers leave in the file (version strings), and a probe: Ghidra's C for a sample of the binary's
// functions is recompiled with each candidate compiler and flag set, and the candidate that reproduces the most
// functions byte for byte wins. The probe is the stronger evidence: clues name a compiler, not its flags, and a raw
// console image has none. The result is a toolchain hypothesis on the binary node, inferred, with its score.
//
// Measured on Lua (Ghidra's C as written, 138 to 146 functions per platform), functions reproduced at -O0/-O1/-O2/
// -O3/-Os: Windows x86-64 0/4/13/13/10, Android AArch64 0/4/16/16/9, raw ARMv6K 0/6/10/10/6 (all built at -O2).
// -O2 and -O3 tie on most small functions, so ties are reported, and the lower level is preferred (the more common
// choice). Linux x86-64 gave too few matches at that sample size (1 at -O2), hence the larger default sample here.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import type { GraphNode, GraphStore, Hypothesis } from "../graph/index.js";
import type { Architecture } from "../tools/engine-analysis.js";
import { recompileCheck, type Toolchain } from "../verify/recompile/recompile-check.js";
import { ghidraPreludeFlags } from "../verify/recompile/ghidra-prelude.js";
import { isRewriteValue } from "../verify/recompile/rewrite-value.js";
import { forEachConcurrently } from "./parallel.js";

export interface ToolchainValue extends Toolchain {
  /** Functions of the sample this toolchain reproduced byte for byte. */
  verified: number;
  /**
   * Summed closeness over the sample: for each function compiled, how near its size is to the original's (1 when it
   * passes, 0 when it does not compile). Ranks candidates whose exact matches tie.
   */
  closeness: number;
  sample: number;
  /** Flag sets that scored the same: the probe cannot tell them apart. */
  ties: string[][];
  /** Compiler version strings found in the binary (untrusted target data). */
  clues: string[];
  /** What else the binary shows about how it was built, for agents writing its C (e.g. fortified library calls). */
  notes?: string[];
}

/**
 * Build settings visible in the binary's imports. A fortified build (_FORTIFY_SOURCE) calls the C library's checked
 * variants (__memcpy_chk, __snprintf_chk...) instead of the plain ones, and so must the C rewritten for it; Ubuntu's
 * GCC enables it by default at -O2. Subagents found this by themselves in the benchmark run.
 */
export function buildNotes(store: GraphStore, binary: string): string[] {
  const checked = store
    .nodesOfKind("function")
    .filter((n) => n.binary === binary && n.label !== undefined && /^__\w+_chk$/.test(n.label))
    .map((n) => n.label as string);
  if (checked.length === 0) return [];
  const names = [...new Set(checked)].sort().slice(0, 6).join(", ");
  return [
    `built with _FORTIFY_SOURCE: the binary calls fortified C library functions (${names}); the C must be compiled ` +
      "the same way (Ubuntu's GCC does it by default at -O2; elsewhere add -D_FORTIFY_SOURCE=2 or 3 and include the " +
      "library headers)",
  ];
}

export interface BinaryFacts {
  architecture: Architecture;
  sharedLibrary: boolean;
  format: "elf" | "pe" | "macho" | "raw";
  clues: string[];
}

const LEVELS = ["-O2", "-O0", "-O1", "-O3", "-Os"];

function installed(cc: string): boolean {
  try {
    execFileSync(cc, ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const GCC_VERSIONS = ["", "-9", "-10", "-11", "-12", "-13", "-14"];
const CLANG_VERSIONS = ["", "-14", "-15", "-17", "-18", "-19"];

/** One compiler driver in each installed version: gcc, gcc-9, gcc-10... */
const versions = (driver: string, suffixes: string[], flags: string[] = []): Toolchain[] =>
  suffixes.map((v) => ({ cc: `${driver}${v}`, flags }));

/** Compilers for the architecture and format, every installed version, the target selected by flags. */
export function candidateCompilers(facts: BinaryFacts): Toolchain[] {
  const arm32 = (march: string): Toolchain[] => [
    ...versions("arm-none-eabi-gcc", [""], [`-march=${march}`]),
    ...versions("arm-linux-gnueabihf-gcc", GCC_VERSIONS, [`-march=${march}`]),
    ...versions("clang", CLANG_VERSIONS, ["--target=arm-none-eabi", `-march=${march.replace("+fp", "")}`]),
  ];
  const byArch: Record<Architecture, Toolchain[]> = {
    x86_64:
      facts.format === "pe"
        ? [
            ...versions("x86_64-w64-mingw32-gcc", [""]),
            ...versions("clang", CLANG_VERSIONS, ["--target=x86_64-w64-windows-gnu"]),
          ]
        : [...versions("gcc", GCC_VERSIONS), ...versions("clang", CLANG_VERSIONS)],
    x86:
      facts.format === "pe"
        ? [
            ...versions("i686-w64-mingw32-gcc", [""]),
            ...versions("clang", CLANG_VERSIONS, ["--target=i686-w64-windows-gnu"]),
          ]
        : [...versions("gcc", GCC_VERSIONS, ["-m32"]), ...versions("clang", CLANG_VERSIONS, ["-m32"])],
    arm64: [
      ...versions("aarch64-linux-gnu-gcc", GCC_VERSIONS),
      ...versions("clang", CLANG_VERSIONS, ["--target=aarch64-linux-gnu"]),
    ],
    "arm-v7": arm32("armv7-a+fp"),
    "arm-v6k": arm32("armv6k+fp"),
    "arm-v5te": arm32("armv5te"),
    mips: [
      ...versions("mips-linux-gnu-gcc", GCC_VERSIONS),
      ...versions("clang", CLANG_VERSIONS, ["--target=mips-linux-gnu"]),
    ],
    mipsel: [
      ...versions("mipsel-linux-gnu-gcc", GCC_VERSIONS),
      ...versions("clang", CLANG_VERSIONS, ["--target=mipsel-linux-gnu"]),
    ],
    ppc: [
      ...versions("powerpc-linux-gnu-gcc", GCC_VERSIONS),
      ...versions("clang", CLANG_VERSIONS, ["--target=powerpc-linux-gnu"]),
    ],
    ppc64: [
      ...versions("powerpc64-linux-gnu-gcc", GCC_VERSIONS),
      ...versions("clang", CLANG_VERSIONS, ["--target=powerpc64-linux-gnu"]),
    ],
  };
  // The unversioned driver is usually a link to one of the versioned ones: keep the first of each actual compiler.
  const seen = new Set<string>();
  return byArch[facts.architecture].filter((t) => {
    if (!installed(t.cc)) return false;
    const identity = `${compilerIdentity(t.cc)} ${t.flags.join(" ")}`;
    if (seen.has(identity)) return false;
    seen.add(identity);
    return true;
  });
}

function compilerIdentity(cc: string): string {
  try {
    return execFileSync(cc, ["--version"], { encoding: "utf8" }).split("\n")[0] ?? cc;
  } catch {
    return cc;
  }
}

/**
 * Candidates the binary's clues name come first: a clue "GCC: (...) 11.5.0" puts the GCC 11 drivers ahead, and
 * "clang version 17.0.6" the Clang 17 ones, so that when scores tie, the compiler the file names wins.
 */
export function orderByClues(candidates: Toolchain[], clues: string[]): Toolchain[] {
  const named = (t: Toolchain): boolean => namedByClues(t, clues);
  return [...candidates.filter(named), ...candidates.filter((t) => !named(t))];
}

/** Whether a version string in the binary names this compiler: same family (GCC or Clang), same major version. */
export function namedByClues(t: Toolchain, clues: string[]): boolean {
  const majors = clues.flatMap((c) => {
    const gcc = /^GCC: \([^)]*\) (\d+)/.exec(c);
    const clang = /^clang version (\d+)/.exec(c);
    return [
      ...(gcc ? [{ family: "gcc", major: gcc[1] }] : []),
      ...(clang ? [{ family: "clang", major: clang[1] }] : []),
    ];
  });
  if (majors.length === 0) return false;
  const id = compilerIdentity(t.cc).toLowerCase();
  return majors.some((m) => {
    const isFamily = m.family === "clang" ? id.includes("clang") : !id.includes("clang");
    return isFamily && new RegExp(`\\b${m.major}\\.\\d`).test(id);
  });
}

/** Flag variants tried at the best optimisation level: instruction set and float ABI on 32-bit ARM, PIC on libraries. */
function variants(facts: BinaryFacts): string[][] {
  const arm32 = facts.architecture.startsWith("arm-");
  const sets: string[][] = [[]];
  const cross = (options: string[][]): void => {
    const next = sets.flatMap((s) => options.map((o) => [...s, ...o]));
    sets.splice(0, sets.length, ...next);
  };
  if (arm32) cross([["-marm"], ["-mthumb"]]);
  if (arm32) cross([["-mfloat-abi=hard"], ["-mfloat-abi=softfp"], ["-mfloat-abi=soft"]]);
  if (facts.sharedLibrary) cross([["-fPIC"]]);
  return sets;
}

function sampleOf(store: GraphStore, binary: string, size: number): { hypothesis: Hypothesis; fn: GraphNode }[] {
  const all = (store.allRecords("hypotheses") as Hypothesis[])
    .filter((h) => h.kind === "rewrite" && h.author.agent === "ghidra-decompiler" && isRewriteValue(h.value))
    .map((h) => ({ hypothesis: h, fn: store.getNode(h.node) }))
    .filter((x): x is { hypothesis: Hypothesis; fn: GraphNode } => x.fn?.binary === binary && x.fn.code !== undefined);
  // Evenly spread over the binary, not its first functions only.
  const step = Math.max(1, Math.ceil(all.length / size));
  return all.filter((_, i) => i % step === 0);
}

/** The first candidate, in trial order, among those tied with the highest score. */
function leader<T extends Score>(tried: T[]): T {
  const top = tried.reduce((a, b) => (rank(b) > rank(a) ? b : a));
  return tried.find((t) => tiedWith(t, top)) ?? top;
}

function tiedWith(a: Score, b: Score): boolean {
  return a.verified === b.verified && Math.abs(a.closeness - b.closeness) <= b.closeness * 0.01;
}

interface Score {
  verified: number;
  closeness: number;
}

/** Exact matches first, then closeness: a single number that orders scores that way. */
const rank = (s: Score): number => s.verified * 1e6 + s.closeness;

async function score(sample: { hypothesis: Hypothesis; fn: GraphNode }[], toolchain: Toolchain): Promise<Score> {
  // Each check is a separate compiler process: run as many at once as there are cores.
  const total: Score = { verified: 0, closeness: 0 };
  await forEachConcurrently(sample, async ({ hypothesis, fn }) => {
    if (!isRewriteValue(hypothesis.value)) return;
    const r = await recompileCheck({
      source: hypothesis.value.source,
      name: hypothesis.value.name,
      original: Buffer.from(fn.code ?? "", "hex"),
      minimumSize: fn.size ?? 0,
      toolchain: { cc: toolchain.cc, flags: [...toolchain.flags, ...ghidraPreludeFlags()] },
    });
    if (r.result === "pass") {
      total.verified++;
      total.closeness += 1;
    } else if (r.reason === "mismatch") {
      // A near miss is evidence too: measured on Clang 17 -O1 Lua, exact matches alone (8 of 329) tied across every
      // Clang release and level. Size, not matching bytes: once lengths differ, bytes compared by position are
      // misaligned and agree only by chance (that measure ranked -O0, with no exact match, first).
      const original = fn.size ?? 0;
      total.closeness += Math.max(0, 1 - Math.abs(r.size - original) / Math.max(r.size, original, 1));
    }
  });
  return total;
}

export class DetectError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DetectError";
  }
}

export async function detectToolchain(
  store: GraphStore,
  binary: string,
  facts: BinaryFacts,
  sampleSize = 400,
): Promise<{ hypothesis?: Hypothesis; value?: ToolchainValue; tried: ({ toolchain: Toolchain } & Score)[] }> {
  const sample = sampleOf(store, binary, sampleSize);
  if (sample.length === 0)
    throw new DetectError(`no decompiled functions of ${binary} to probe with; run atlas decompile first`);
  const compilers = candidateCompilers(facts);
  if (compilers.length === 0) {
    throw new DetectError(`no compiler installed for ${facts.architecture} (${facts.format}); run scripts/setup.sh`);
  }
  const tried: ({ toolchain: Toolchain } & Score)[] = [];
  const attempt = async (toolchain: Toolchain, on = sample): Promise<Score> => {
    const result = await score(on, toolchain);
    if (on === sample) tried.push({ toolchain, ...result });
    return result;
  };
  const ordered = orderByClues(compilers, facts.clues);
  // A version string in the file names the compiler more surely than the probe, which only separates releases by
  // small differences (on Lua built with GCC 13, GCC 11 came out slightly closer). When the clues name installed
  // compilers, the probe chooses the flags among those only.
  const named = ordered.filter((c) => namedByClues(c, facts.clues));
  const base = variants(facts)[0] ?? [];
  // Stage 1, which compiler: each at -O2 on half the sample; the best three go on. (A half dropped the right
  // Clang release on Lua: too few functions to rank eleven compilers.)
  const half = sample.filter((_, i) => i % 2 === 0);
  const screened: { compiler: Toolchain; rank: number }[] = [];
  for (const c of named.length > 0 ? [] : ordered) {
    screened.push({
      compiler: c,
      rank: rank(await attempt({ cc: c.cc, flags: [...c.flags, ...base, "-O2"] }, half)),
    });
  }
  const finalists =
    named.length > 0
      ? named
      : [...screened]
          .sort((a, b) => b.rank - a.rank)
          .slice(0, 3)
          .map((s) => s.compiler);
  // Stage 2, which level: every level for the finalists, on the whole sample, in clue order.
  for (const c of ordered.filter((c) => finalists.includes(c))) {
    for (const level of LEVELS) await attempt({ cc: c.cc, flags: [...c.flags, ...base, level] });
  }
  if (tried.length === 0) return { tried };
  // Stage 3, the variants (instruction set, float ABI, PIC) at the best compiler and level.
  const best1 = leader(tried);
  const level = best1.toolchain.flags[best1.toolchain.flags.length - 1] ?? "-O2";
  const compiler = ordered.find(
    (c) => c.cc === best1.toolchain.cc && best1.toolchain.flags.join(" ").startsWith(c.flags.join(" ")),
  );
  for (const v of variants(facts).slice(1)) {
    if (compiler !== undefined) await attempt({ cc: compiler.cc, flags: [...compiler.flags, ...v, level] });
  }
  // Candidates with as many exact matches and within 1% of the best closeness are tied: the difference is noise. The
  // first of them in trial order wins (clue-named compilers first, -O2 first, the base variant first); on raw ARM Lua
  // the soft-float variant came out 1% closer than the hard-float build's own setting.
  const best = leader(tried);
  if (best.closeness === 0) return { tried };
  const value: ToolchainValue = {
    cc: best.toolchain.cc,
    flags: best.toolchain.flags,
    verified: best.verified,
    closeness: Math.round(best.closeness * 100) / 100,
    sample: sample.length,
    ties: tried.filter((t) => t !== best && tiedWith(t, best)).map((t) => [t.toolchain.cc, ...t.toolchain.flags]),
    clues: facts.clues,
    ...(buildNotes(store, binary).length > 0 ? { notes: buildNotes(store, binary) } : {}),
  };
  const id = `hyp_${createHash("sha256")
    .update(`${binary}\ntoolchain\n${JSON.stringify(value)}`)
    .digest("hex")
    .slice(0, 32)}`;
  const hypothesis: Hypothesis = {
    schema_version: 1,
    id,
    node: binary,
    kind: "toolchain",
    value,
    confidence: "inferred",
    evidence: [binary, ...sample.slice(0, 8).map((s) => s.fn.id)],
    author: { agent: "toolchain-probe" },
  };
  if (store.getHypothesis(id) === undefined) store.proposeHypothesis(hypothesis);
  return { hypothesis, value, tried };
}

/**
 * The toolchain inferred for a binary: its latest toolchain hypothesis. A later detection supersedes an earlier one
 * (the detector improves, and scores from different samples do not compare): picking the best score instead kept a
 * soft-float result from an older run on raw ARM Lua, and with it the wrong libraries.
 */
export function binaryToolchain(store: GraphStore, binary: string): ToolchainValue | undefined {
  const values = store
    .hypothesesFor(binary, "toolchain")
    .map((h) => h.value as ToolchainValue)
    .filter((v) => typeof v?.cc === "string" && Array.isArray(v.flags));
  return values[values.length - 1];
}
