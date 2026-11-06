// Which code the recorded behaviours exercise: atlas coverage behaviour. The program is rebuilt as atlas lift --link
// builds it, each behaviour is replayed with ATLAS_COVERAGE (link.py: the translated functions that ran, written at
// exit), and the report says how many of the translated functions the acceptance tests reach, what each behaviour
// adds, and the largest functions none reaches: where the next behaviour to record would exercise the most code
// no test checks. x86-64 (link.py) and AArch64 (a64link.py) Linux programs for now. Runs the rebuilt program: the caller asked for it.
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { GraphStore } from "../graph/index.js";
import { runScenario } from "../verify/replay/run-scenario.js";
import { fileSha256 } from "./file-hash.js";
import { NotFoundError } from "./function-context.js";
import { liftBinary } from "./lift-binary.js";
import { linkBase, linkBinary } from "./link-binary.js";
import { binaryId } from "./load-binary.js";
import type { BehaviourValue } from "./record-behaviour.js";

export interface CoverageReport {
  translated: number;
  covered: number;
  behaviours: { hypothesis: string; argv: string[]; reached: number; added: number }[];
  /** The largest translated functions no behaviour reaches, largest first. */
  uncovered: { id: string; address: string; label?: string; size: number }[];
}

export async function coverageBehaviour(store: GraphStore, original: string, top = 20): Promise<CoverageReport> {
  const binary = binaryId(await fileSha256(original));
  if (store.getNode(binary) === undefined) throw new NotFoundError(`${original} is not loaded; atlas load it first`);
  const architecture = store.getNode(binary)?.architecture;
  if (architecture !== "x86_64" && architecture !== "arm64") {
    throw new Error("coverage is measured on x86-64 and AArch64 Linux programs for now (ATLAS_COVERAGE)");
  }
  const behaviours = store.hypothesesFor(binary, "behaviour").filter((h) => h.confidence !== "rejected");
  if (behaviours.length === 0) throw new NotFoundError(`no behaviour recorded for ${original}`);
  const dir = await mkdtemp(join(tmpdir(), "atlas-coverage-"));
  try {
    const lifted = await liftBinary(store, binary, dir, original, linkBase(original));
    const linked = await linkBinary(store, binary, original, dir, lifted.addresses);
    const covered = new Set<number>();
    const report: CoverageReport = { translated: lifted.addresses.length, covered: 0, behaviours: [], uncovered: [] };
    for (const h of behaviours) {
      const file = join(dir, `coverage-${report.behaviours.length}.txt`);
      await runScenario(linked.executable, (h.value as BehaviourValue).scenario, { ATLAS_COVERAGE: file });
      const reached = (await readFile(file, "utf8").catch(() => ""))
        .split("\n")
        .filter((l) => l !== "")
        .map((l) => Number(l));
      const before = covered.size;
      for (const a of reached) covered.add(a);
      report.behaviours.push({
        hypothesis: h.id,
        argv: (h.value as BehaviourValue).scenario.argv,
        reached: reached.length,
        added: covered.size - before,
      });
    }
    report.covered = covered.size;
    const translated = new Set(lifted.addresses);
    report.uncovered = store
      .nodesOfKind("function")
      .filter((f) => f.binary === binary && f.address !== undefined)
      .map((f) => ({ f, address: Number(BigInt(f.address as string)) }))
      .filter(({ address }) => translated.has(address) && !covered.has(address))
      .sort((a, b) => (b.f.size ?? 0) - (a.f.size ?? 0))
      .slice(0, top)
      .map(({ f, address }) => ({
        id: f.id,
        address: `0x${address.toString(16)}`,
        ...(f.label !== undefined ? { label: f.label } : {}),
        size: f.size ?? 0,
      }));
    return report;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
