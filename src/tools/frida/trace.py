"""Traces a native program with Frida: which functions run, and what their argument registers hold.

Reads a JSON request (path in argv[1]), writes a JSON answer to stdout:
  request: {"program": str, "argv": [str], "stdin": str | null, "functions": [int], "samples": int,
            "timeout": float}
  answer:  {"exit": "exited" | "timeout" | "detached", "module_base": str,
            "functions": {"0x...": {"calls": int, "args": [{"pointer": int, "integer": int, "zero": int}] * 6,
                                     "returned": int, "result_pointer": int}}}

Addresses in and out are the binary's own (as in the graph): a position-independent ELF (ET_DYN) is at 0 there, so
its runtime base is added; a fixed-address one (ET_EXEC) runs where the graph has it.
Each function's first `samples` calls are classified per integer argument register (System V x86-64: rdi, rsi,
rdx, rcx, r8, r9): pointer when the value falls in a mapped range of the process, zero, or another integer. Every
call is counted. This RUNS the target natively, under the operator's account: only for targets the operator chose
to run. Linux x86-64 for now.
"""

import json
import sys
import threading

import frida

AGENT = r"""
const fns = %FUNCTIONS%;
const delta = ptr(%DELTA%);
const samples = %SAMPLES%;
const regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
const stats = {};
const kind = (v) => v.isNull() ? "zero" : (Process.findRangeByAddress(v) !== null ? "pointer" : "integer");
for (const a of fns) {
  const s = { calls: 0, args: regs.map(() => ({ pointer: 0, integer: 0, zero: 0 })), returned: 0, result_pointer: 0 };
  stats["0x" + a.toString(16)] = s;
  try {
    Interceptor.attach(delta.add(a), {
      onEnter(args) {
        s.calls++;
        this.sample = s.calls <= samples;
        if (this.sample) regs.forEach((r, i) => { s.args[i][kind(this.context[r])]++; });
      },
      onLeave(ret) {
        if (!this.sample) return;
        s.returned++;
        if (!ret.isNull() && Process.findRangeByAddress(ret) !== null) s.result_pointer++;
      },
    });
  } catch (e) { s.error = String(e); }
}
// At exit the statistics go to Atlas before the process ends (the ack holds the exiting thread until received).
for (const name of ["exit", "_exit"]) {
  const at = Module.findGlobalExportByName(name);
  if (at !== null) Interceptor.attach(at, { onEnter() { send({ final: stats }); recv("ack", () => {}).wait(); } });
}
rpc.exports = { stats: () => stats };
"""


def main():
    request = json.load(open(sys.argv[1]))
    device = frida.get_local_device()
    pid = device.spawn([request["program"], *request.get("argv", [])], stdio="pipe")
    session = device.attach(pid)
    done = threading.Event()
    state = {"exit": "timeout"}
    session.on("detached", lambda reason, crash: (state.update(exit="exited" if reason == "process-terminated" else "detached"), done.set()))
    probe = session.create_script("rpc.exports = { base: () => Process.enumerateModules()[0].base.toString() };")
    probe.load()
    module_base = int(probe.exports_sync.base(), 16)
    probe.unload()
    with open(request["program"], "rb") as f:
        header = f.read(18)
    if header[:4] != b"\x7fELF":
        raise SystemExit(json.dumps({"error": "not an ELF program"}))
    position_independent = int.from_bytes(header[16:18], "little") == 3  # ET_DYN
    delta = module_base if position_independent else 0
    source = (
        AGENT.replace("%FUNCTIONS%", json.dumps(request["functions"]))
        .replace("%DELTA%", json.dumps(hex(delta)))
        .replace("%SAMPLES%", str(int(request.get("samples", 16))))
    )
    script = session.create_script(source)
    latest = {}
    final = {}

    def on_message(message, _data):
        if message.get("type") == "send" and "final" in message.get("payload", {}):
            final.update(message["payload"]["final"])
            script.post({"type": "ack"})

    script.on("message", on_message)
    script.load()
    stdin = request.get("stdin")
    device.resume(pid)
    if stdin is not None:
        device.input(pid, stdin.encode())
    # Statistics are read while the process lives (they go with it): poll until it ends or the time is up.
    deadline = float(request.get("timeout", 30))
    waited = 0.0
    while not done.is_set() and waited < deadline:
        try:
            latest = script.exports_sync.stats()
        except Exception:
            break
        done.wait(0.05)
        waited += 0.05
    if not done.is_set():
        try:
            latest = script.exports_sync.stats()
        except Exception:
            pass
        device.kill(pid)
    print(json.dumps({"exit": state["exit"], "module_base": hex(module_base), "functions": final or latest}))


if __name__ == "__main__":
    main()
