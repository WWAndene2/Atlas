// The whole-program check of atlas run: when behaviours are recorded for a binary (atlas record behaviour), the
// binary is rebuilt as atlas lift --link builds it (translations, verified rewrites in their place where the
// platform allows) and every behaviour is replayed on that program. So the report says how much of what the program
// does the reconstruction reproduces, beside how many functions are verified. The program is built in a temporary
// directory and removed after; the replay records the outcome on each behaviour, naming the program by its SHA-256.
// Nothing is built when no behaviour is recorded: the step costs nothing then.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { GraphStore } from "../graph/index.js";
import type { EngineInput } from "../tools/engine-analysis.js";
import { liftBinary } from "./lift-binary.js";
import { linkBase, linkBinary } from "./link-binary.js";
import { replayBehaviour } from "./replay-behaviour.js";

export interface ReconstructionCheck {
  recorded: number;
  reproduced: number;
  /** The behaviours the reconstruction did not reproduce, and where it differed. */
  failed: { hypothesis: string; argv: string[]; differences: string[] }[];
  /** SHA-256 of the program the behaviours were replayed on. */
  reconstruction: string;
}

export async function checkReconstruction(
  store: GraphStore,
  binary: string,
  input: EngineInput,
): Promise<ReconstructionCheck | undefined> {
  const recorded = store.hypothesesFor(binary, "behaviour").filter((h) => h.confidence !== "rejected").length;
  if (recorded === 0) return undefined;
  if (input.raw !== undefined) throw new Error("a raw image is not linked into a program: behaviours not replayed");
  const dir = await mkdtemp(join(tmpdir(), "atlas-reconstruction-"));
  try {
    const lifted = await liftBinary(store, binary, dir, input.path, linkBase(input.path));
    const linked = await linkBinary(store, binary, input.path, dir, lifted.addresses);
    const replay = await replayBehaviour(store, input.path, linked.executable);
    const failed = replay.results
      .filter((r) => r.result === "fail")
      .map((r) => ({ hypothesis: r.hypothesis, argv: r.argv, differences: r.differences }));
    return { recorded, reproduced: recorded - failed.length, failed, reconstruction: replay.reconstruction };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
