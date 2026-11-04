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
import { repositoryPath } from "../graph/index.js";
import type { Architecture } from "../tools/engine-analysis.js";
import { recompileCheck, type Toolchain } from "../verify/recompile/recompile-check.js";
import { isRewriteValue } from "../verify/recompile/rewrite-value.js";

export interface ToolchainValue extends Toolchain {
  /** Functions of the sample this toolchain reproduced byte for byte. */
  verified: number;
  sample: number;
  /** Flag sets that scored the same: the probe cannot tell them apart. */
  ties: string[][];
  /** Compiler version strings found in the binary (untrusted target data). */
  clues: string[];
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

/** Compilers for the architecture and format, with the flags that select the target, among those installed. */
export function candidateCompilers(facts: BinaryFacts): Toolchain[] {
  const arm32 = (march: string): Toolchain[] => [
    { cc: "arm-none-eabi-gcc", flags: [`-march=${march}`] },
    { cc: "arm-linux-gnueabihf-gcc", flags: [`-march=${march}`] },
  ];
  const byArch: Record<Architecture, Toolchain[]> = {
    x86_64:
      facts.format === "pe"
        ? [{ cc: "x86_64-w64-mingw32-gcc", flags: [] }]
        : [
            { cc: "gcc", flags: [] },
            { cc: "clang", flags: [] },
          ],
    x86: facts.format === "pe" ? [{ cc: "i686-w64-mingw32-gcc", flags: [] }] : [{ cc: "gcc", flags: ["-m32"] }],
    arm64: [
      { cc: "aarch64-linux-gnu-gcc", flags: [] },
      { cc: "clang", flags: ["--target=aarch64-linux-gnu"] },
    ],
    "arm-v7": arm32("armv7-a+fp"),
    "arm-v6k": arm32("armv6k+fp"),
    "arm-v5te": arm32("armv5te"),
  };
  return byArch[facts.architecture].filter((t) => installed(t.cc));
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

async function score(sample: { hypothesis: Hypothesis; fn: GraphNode }[], toolchain: Toolchain): Promise<number> {
  let verified = 0;
  const ghidraTypes = repositoryPath("src", "verify", "recompile", "ghidra-types.h");
  for (const { hypothesis, fn } of sample) {
    if (!isRewriteValue(hypothesis.value)) continue;
    const r = await recompileCheck({
      source: hypothesis.value.source,
      name: hypothesis.value.name,
      original: Buffer.from(fn.code ?? "", "hex"),
      minimumSize: fn.size ?? 0,
      toolchain: { cc: toolchain.cc, flags: [...toolchain.flags, "-include", ghidraTypes] },
    });
    if (r.result === "pass") verified++;
  }
  return verified;
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
): Promise<{ hypothesis?: Hypothesis; value?: ToolchainValue; tried: { toolchain: Toolchain; verified: number }[] }> {
  const sample = sampleOf(store, binary, sampleSize);
  if (sample.length === 0)
    throw new DetectError(`no decompiled functions of ${binary} to probe with; run atlas decompile first`);
  const compilers = candidateCompilers(facts);
  if (compilers.length === 0) {
    throw new DetectError(`no compiler installed for ${facts.architecture} (${facts.format}); run scripts/setup.sh`);
  }
  const tried: { toolchain: Toolchain; verified: number }[] = [];
  const attempt = async (toolchain: Toolchain): Promise<number> => {
    const verified = await score(sample, toolchain);
    tried.push({ toolchain, verified });
    return verified;
  };
  // Stage 1: compiler and optimisation level, with the first variant. Stage 2: the variants, at the best level.
  const base = variants(facts)[0] ?? [];
  for (const c of compilers)
    for (const level of LEVELS) await attempt({ cc: c.cc, flags: [...c.flags, ...base, level] });
  const best1 = tried.reduce((a, b) => (b.verified > a.verified ? b : a));
  const level = best1.toolchain.flags[best1.toolchain.flags.length - 1] ?? "-O2";
  const compiler = compilers.find((c) => c.cc === best1.toolchain.cc) ?? compilers[0];
  for (const v of variants(facts).slice(1)) {
    if (compiler !== undefined) await attempt({ cc: compiler.cc, flags: [...compiler.flags, ...v, level] });
  }
  // The first of the best in trial order wins: -O2 before -O3, the base variant before others.
  const top = Math.max(...tried.map((t) => t.verified));
  if (top === 0) return { tried };
  const best = tried.find((t) => t.verified === top) as { toolchain: Toolchain; verified: number };
  const value: ToolchainValue = {
    cc: best.toolchain.cc,
    flags: best.toolchain.flags,
    verified: top,
    sample: sample.length,
    ties: tried.filter((t) => t.verified === top && t !== best).map((t) => [t.toolchain.cc, ...t.toolchain.flags]),
    clues: facts.clues,
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

/** The toolchain inferred for a binary: its best-scoring toolchain hypothesis, if any. */
export function binaryToolchain(store: GraphStore, binary: string): ToolchainValue | undefined {
  const values = store
    .hypothesesFor(binary, "toolchain")
    .map((h) => h.value as ToolchainValue)
    .filter((v) => typeof v?.cc === "string" && Array.isArray(v.flags));
  return values.sort((a, b) => b.verified / b.sample - a.verified / a.sample)[0];
}
