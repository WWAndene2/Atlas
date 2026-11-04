// Public entry point of the Ghidra adapter: re-exports only.
export { GhidraExportError, parseGhidraExport } from "./ghidra-export.js";
export { parseGhidraDecompile, type DecompiledFunction } from "./ghidra-decompile.js";
export {
  GHIDRA_VERSION,
  GhidraUnavailableError,
  analyseWithGhidra,
  decompileWithGhidra,
  locateGhidra,
} from "./ghidra-headless.js";
