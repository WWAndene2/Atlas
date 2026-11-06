// Finds the function a failing behaviour comes from: atlas blame behaviour. The rebuilt program (translations and
// verified rewrites, as atlas lift --link builds it) does not reproduce a recorded behaviour; on an x86-64 Linux
// host the original's own machine code can stand in for any function (link.py's native list), so the functions
// still translated or rewritten are narrowed by delta debugging to the smallest set that still fails: a translator
// defect or a wrong rewrite, with the translated callers on its path (a native caller reaches its callees natively). First the two ends are checked: the program as rebuilt must fail
// and the program with every function native must pass, else there is nothing to blame (or the cause is not a
// function: the environment, the C library's calls). Runs the rebuilt programs natively: the caller asked for it.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { GraphStore } from "../graph/index.js";
import { differences, runScenario } from "../verify/replay/run-scenario.js";
import { fileSha256 } from "./file-hash.js";
import { NotFoundError } from "./function-context.js";
import { liftBinary } from "./lift-binary.js";
import { linkBase, linkBinary } from "./link-binary.js";
import { binaryId } from "./load-binary.js";
import type { BehaviourValue } from "./record-behaviour.js";

export interface BlameResult {
  behaviour: string;
  /** reproduced: nothing to blame; not_functions: it fails with every function native too; blamed: see culprits. */
  result: "reproduced" | "not_functions" | "blamed";
  /**
   * The smallest set of functions whose translation or rewrite the failure needs: the faulty one, marked likely
   * (it calls no other member), and the translated callers on the path to it.
   */
  culprits: { id: string; address: string; label?: string; rewritten: boolean; likely: boolean }[];
  /** How the behaviour differs with every function translated, as the replay check reports it. */
  differences: string[];
  rebuilds: number;
}

export async function blameBehaviour(store: GraphStore, original: string, behaviour: string): Promise<BlameResult> {
  const binary = binaryId(await fileSha256(original));
  if (store.getNode(binary) === undefined) throw new NotFoundError(`${original} is not loaded; atlas load it first`);
  const h = store.getHypothesis(behaviour);
  if (h === undefined || h.kind !== "behaviour" || h.node !== binary) {
    throw new NotFoundError(`${behaviour} is not a behaviour recorded for ${original}`);
  }
  if (store.getNode(binary)?.architecture !== "x86_64") {
    throw new Error("blame runs functions as the original's code: x86-64 Linux programs on an x86-64 host for now");
  }
  const value = h.value as BehaviourValue;
  const dir = await mkdtemp(join(tmpdir(), "atlas-blame-"));
  let rebuilds = 0;
  try {
    const lifted = await liftBinary(store, binary, dir, original, linkBase(original));
    const all = lifted.addresses;
    // The behaviour's outcome with these functions translated (or rewritten) and every other one native.
    const failsWith = async (translated: Set<number>): Promise<string[]> => {
      rebuilds++;
      const native = all.filter((a) => !translated.has(a));
      const linked = await linkBinary(store, binary, original, dir, all, native);
      return differences(value.expected, await runScenario(linked.executable, value.scenario), value.scenario.vary);
    };
    const whole = await failsWith(new Set(all));
    if (whole.length === 0) return { behaviour, result: "reproduced", culprits: [], differences: [], rebuilds };
    if ((await failsWith(new Set())).length > 0) {
      return { behaviour, result: "not_functions", culprits: [], differences: whole, rebuilds };
    }
    // Delta debugging (Zeller's ddmin) over the functions kept translated: the smallest set that still fails.
    // A native function calls its callees as native code too, so the failure needs the faulty function and the
    // translated callers on its path: a set, not always one function.
    let suspects = all;
    let parts = 2;
    while (suspects.length >= 2) {
      const size = Math.ceil(suspects.length / parts);
      const subsets = Array.from({ length: Math.ceil(suspects.length / size) }, (_, k) =>
        suspects.slice(k * size, (k + 1) * size),
      );
      let next: number[] | undefined;
      for (const subset of subsets) {
        if ((await failsWith(new Set(subset))).length > 0) {
          next = subset;
          parts = 2;
          break;
        }
      }
      if (next === undefined && subsets.length > 2) {
        for (const subset of subsets) {
          const complement = suspects.filter((a) => !subset.includes(a));
          if ((await failsWith(new Set(complement))).length > 0) {
            next = complement;
            parts = Math.max(parts - 1, 2);
            break;
          }
        }
      }
      if (next !== undefined) {
        suspects = next;
        continue;
      }
      if (parts >= suspects.length) break;
      parts = Math.min(suspects.length, parts * 2);
    }
    const byAddress = new Map(
      store
        .nodesOfKind("function")
        .filter((f) => f.binary === binary && f.address !== undefined)
        .map((f) => [Number(BigInt(f.address as string)), f]),
    );
    // The likely culprit is the end of the path: a member that calls no other member (by the graph's call edges);
    // the members that do are the callers leading to it.
    const inSet = new Set(suspects.map((a) => byAddress.get(a)?.id).filter((id) => id !== undefined));
    const culprits = suspects.map((a) => {
      const fn = byAddress.get(a);
      const rewritten =
        fn !== undefined && store.hypothesesFor(fn.id, "rewrite").some((r) => r.confidence === "verified");
      const callsMember = fn !== undefined && store.edgesFrom(fn.id, "calls").some((e) => inSet.has(e.to));
      return {
        id: fn?.id ?? `0x${a.toString(16)}`,
        address: `0x${a.toString(16)}`,
        ...(fn?.label !== undefined ? { label: fn.label } : {}),
        rewritten,
        likely: !callsMember,
      };
    });
    return { behaviour, result: "blamed", culprits, differences: whole, rebuilds };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
