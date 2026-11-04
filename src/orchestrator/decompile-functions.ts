// Decompiles a binary's functions with Ghidra and adds each one's C to the graph as a rewrite hypothesis, the
// starting point an agent improves until it recompiles to the original bytes.
import type { GraphStore, Hypothesis } from "../graph/index.js";
import type { EngineInput } from "../tools/engine-analysis.js";
import { decompileWithGhidra, locateGhidra } from "../tools/ghidra/index.js";
import { fileSha256 } from "./file-hash.js";
import { functionId } from "./load-binary.js";
import { proposeRewrite } from "./propose-rewrite.js";

export interface DecompileOutcome {
  proposed: Hypothesis[];
  /** Functions Ghidra could not decompile, or that are not in the graph (load the binary first). */
  skipped: { address: string; reason: string }[];
}

/** C identifiers only: Ghidra's labels can hold characters a C name cannot (from symbols, or its own @ suffixes). */
function cName(label: string): string | undefined {
  return /^[A-Za-z_]\w*$/.test(label) ? label : undefined;
}

export async function decompileFunctions(
  store: GraphStore,
  input: EngineInput,
  addresses?: string[],
): Promise<DecompileOutcome> {
  const sha256 = await fileSha256(input.path);
  const functions = await decompileWithGhidra(input, { installDir: locateGhidra() }, addresses);
  const outcome: DecompileOutcome = { proposed: [], skipped: [] };
  store.transaction(() => {
    for (const f of functions) {
      const id = functionId(sha256, f.address);
      const name = cName(f.label);
      if (store.getNode(id) === undefined) outcome.skipped.push({ address: f.address, reason: "not in the graph" });
      else if (f.c === undefined) outcome.skipped.push({ address: f.address, reason: f.error ?? "no C" });
      else if (name === undefined)
        outcome.skipped.push({ address: f.address, reason: `label ${f.label} is not a C name` });
      else {
        outcome.proposed.push(
          proposeRewrite(
            store,
            id,
            { language: "c", source: f.c, name, prelude: "ghidra" },
            "ghidra-decompiler",
            "inferred",
          ),
        );
      }
    }
  });
  return outcome;
}
