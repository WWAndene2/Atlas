// Sets the functions a second engine (Rizin) finds beside those in the graph (Ghidra's): where both engines agree
// on an entry, the function is better founded; where only one finds it, an analyst or agent should look. The
// result is recorded as engine evidence on the binary so later work can cite it.
import { createHash } from "node:crypto";
import type { GraphStore } from "../graph/index.js";
import type { EngineInput } from "../tools/engine-analysis.js";
import { fileSha256 } from "./file-hash.js";
import { NotFoundError } from "./function-context.js";
import { binaryId } from "./load-binary.js";
import { resolveTarget } from "./resolve-target.js";
import { locateRizin, RIZIN_VERSION, rizinFunctions } from "../tools/rizin/index.js";

export interface CrossCheck {
  binary: string;
  evidence: string;
  /** Entries both engines found. */
  agreed: number;
  /** Entries only in the graph, and only Rizin found (addresses). */
  onlyGraph: string[];
  onlyRizin: string[];
  /** Entries both found with a different size. */
  sizeDiffers: { address: string; graph: number; rizin: number }[];
}

export async function crossCheckFunctions(
  store: GraphStore,
  binary: string,
  input: EngineInput,
  now = new Date(),
): Promise<CrossCheck> {
  const found = await rizinFunctions(locateRizin(), input);
  const rizin = new Map(found.map((f) => [BigInt(f.address), f]));
  const graph = new Map(
    store
      .nodesOfKind("function")
      .filter((n) => n.binary === binary && n.address !== undefined)
      .map((n) => [BigInt(n.address as string), n]),
  );
  const hex = (a: bigint) => `0x${a.toString(16)}`;
  const onlyGraph = [...graph.keys()].filter((a) => !rizin.has(a)).sort((a, b) => (a < b ? -1 : 1));
  const onlyRizin = [...rizin.keys()].filter((a) => !graph.has(a)).sort((a, b) => (a < b ? -1 : 1));
  const sizeDiffers = [...graph.entries()]
    .filter(([a, n]) => rizin.has(a) && n.size !== undefined && rizin.get(a)?.size !== n.size)
    .map(([a, n]) => ({ address: hex(a), graph: n.size as number, rizin: rizin.get(a)?.size as number }));
  const agreed = graph.size - onlyGraph.length;
  const evidence = `evd_${createHash("sha256").update(`rizin-cross-check\n${RIZIN_VERSION}\n${binary}`).digest("hex").slice(0, 32)}`;
  store.putEvidence({
    schema_version: 1,
    id: evidence,
    source: "engine",
    tool: { name: "rizin", version: RIZIN_VERSION },
    summary:
      `rizin ${RIZIN_VERSION} cross-check of ${binary}: ${agreed} function entries agreed, ` +
      `${onlyGraph.length} only in the graph, ${onlyRizin.length} only found by Rizin, ${sizeDiffers.length} with another size`,
    limitations: ["entries compared by address only; Rizin's sizes count its own basic blocks"],
    created_at: now.toISOString(),
  });
  return { binary, evidence, agreed, onlyGraph: onlyGraph.map(hex), onlyRizin: onlyRizin.map(hex), sizeDiffers };
}

/** Every binary of a file (a container may hold several), each already loaded. Shared by the CLI and MCP. */
export async function crossCheckFile(
  store: GraphStore,
  path: string,
  raw?: EngineInput["raw"],
): Promise<(CrossCheck & { label: string })[]> {
  const target = await resolveTarget(path, raw);
  try {
    const out = [];
    for (const b of target.binaries) {
      const binary = binaryId(await fileSha256(b.input.path));
      if (store.getNode(binary) === undefined) throw new NotFoundError(`${b.label} is not loaded; atlas load it first`);
      out.push({ label: b.label, ...(await crossCheckFunctions(store, binary, b.input)) });
    }
    return out;
  } finally {
    await target.dispose();
  }
}
