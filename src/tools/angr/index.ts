// Public entry point of the angr adapter: re-exports only.
export {
  AngrUnavailableError,
  checkEquivalence,
  locateAngr,
  type CodeVersion,
  type EquivalenceAnswer,
} from "./angr-equivalence.js";
