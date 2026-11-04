/**
 * CPU families Atlas can name for a raw image. Engine-neutral: each adapter maps them to its own identifiers.
 * arm-v6k is the ARM11 of the Nintendo 3DS; arm-v7 covers Cortex-A cores in ARM mode.
 */
export const ARCHITECTURES = ["x86", "x86_64", "arm-v5te", "arm-v6k", "arm-v7", "arm64"] as const;
export type Architecture = (typeof ARCHITECTURES)[number];

/** A binary to analyse. Without raw, the engine reads the file's own header (ELF, PE, Mach-O...). */
export interface EngineInput {
  path: string;
  /** For bytes with no header (a 3DS code.bin, a ROM dump): the CPU and the address the bytes are loaded at. */
  raw?: { architecture: Architecture; base: string };
}

// What every engine adapter returns: the engine-neutral result of analysing one binary. The loader turns it into
// graph records, so adding an engine means one adapter producing this, not a change to the loader.

export interface EngineFunction {
  /** Entry address, lowercase hex with 0x, at the binary's own (unrebased) addresses. */
  address: string;
  size: number;
  /** The engine's raw label (FUN_00401000, or a name from leftover symbols). Not a name hypothesis. */
  label: string;
  /** A stub that only jumps to another function (a PLT entry, for example). */
  thunk: boolean;
}

export interface EngineCall {
  /** Entry address of the calling function. */
  from: string;
  /** Entry address of the called function. */
  to: string;
}

export interface EngineString {
  address: string;
  value: string;
  /** Entry addresses of the functions whose code refers to the string, all in functions. */
  readers: string[];
}

export interface EngineAnalysis {
  tool: { name: string; version: string };
  /** SHA-256 of the analysed file, lowercase hex. */
  sha256: string;
  functions: EngineFunction[];
  /** One entry per distinct caller and callee pair, both in functions. */
  calls: EngineCall[];
  strings: EngineString[];
  /** What the engine's result cannot be trusted for, carried into the evidence record. */
  limitations: string[];
}
