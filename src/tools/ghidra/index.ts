// Public entry point of the Ghidra adapter: re-exports only.
export { GhidraExportError, parseGhidraExport } from "./ghidra-export.js";
export { GHIDRA_VERSION, GhidraUnavailableError, analyseWithGhidra, locateGhidra } from "./ghidra-headless.js";
