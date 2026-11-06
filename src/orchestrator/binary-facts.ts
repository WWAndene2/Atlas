// What the file of a binary says about how to rebuild it: its architecture, format, whether it is a shared library,
// and the compiler version strings left in it. Input to toolchain detection.
import { headerArchitecture, isSharedLibrary } from "../tools/binary-header.js";
import { binaryKind } from "../tools/binary-kind.js";
import { fileSource } from "../tools/byte-source.js";
import { compilerClues } from "../tools/compiler-clues.js";
import type { EngineInput } from "../tools/engine-analysis.js";
import type { BinaryFacts } from "./detect-toolchain.js";

export class FactsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FactsError";
  }
}

export function binaryFacts(input: EngineInput): BinaryFacts {
  const source = fileSource(input.path);
  try {
    const head = source.read(0, 4096);
    const kind = binaryKind(head);
    const architecture = input.raw?.architecture ?? headerArchitecture(head);
    if (architecture === undefined) {
      throw new FactsError(`the architecture of ${input.path} is not known; for a raw image give --arch and --base`);
    }
    const format =
      input.raw !== undefined
        ? "raw"
        : kind === "pe"
          ? "pe"
          : kind === "macho" || kind === "macho-fat"
            ? "macho"
            : "elf";
    return { architecture, format, sharedLibrary: isSharedLibrary(head), clues: compilerClues(source) };
  } finally {
    source.close();
  }
}
