// Public entry point of the VEX static recompilation adapter: re-exports only.
export {
  crosslinkProgram,
  linkProgram,
  type CrosslinkOutcome,
  type CrosslinkRequest,
  type LinkOutcome,
  type LinkRequest,
} from "./vex-link.js";
export { ARCH, bigEndian, liftFunctions, RUNTIME_HEADER, type LiftedFunction } from "./vex-lift.js";
