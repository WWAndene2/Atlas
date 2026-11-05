// Public entry point of the Frida adapter: re-exports only.
export {
  FRIDA_VERSION,
  FridaUnavailableError,
  locateFrida,
  traceProgram,
  type ArgumentObservation,
  type FunctionTrace,
  type TraceResult,
} from "./frida-trace.js";
