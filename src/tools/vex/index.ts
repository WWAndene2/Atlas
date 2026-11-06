// Public entry point of the VEX static recompilation adapter: re-exports only.
export {
  a64linkProgram,
  type A64linkOutcome,
  type A64linkRequest,
  crosslinkProgram,
  linkProgram,
  type CrosslinkOutcome,
  type CrosslinkRequest,
  type LinkOutcome,
  type LinkRequest,
  winlinkProgram,
  type WinlinkOutcome,
  type WinlinkRequest,
} from "./vex-link.js";
export { ARCH, bigEndian, liftFunctions, RUNTIME_HEADER, type LiftedFunction } from "./vex-lift.js";
