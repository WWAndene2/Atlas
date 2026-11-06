// Public entry point of the VEX static recompilation adapter: re-exports only.
export { linkProgram, type LinkOutcome, type LinkRequest } from "./vex-link.js";
export { bigEndian, liftFunctions, RUNTIME_HEADER, type LiftedFunction } from "./vex-lift.js";
