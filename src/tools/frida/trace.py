"""Traces a native program with Frida: which functions run, and what their argument registers hold.

Reads a JSON request (path in argv[1]), writes a JSON answer to stdout:
  request: {"program": str, "argv": [str], "stdin": str | null, "functions": [int], "samples": int,
            "timeout": float, "captures"?: int, "capture_file"?: path}
With captures, the first `captures` calls of each function are also written to capture_file (one JSON line each:
the registers at entry and the 4 KiB pages they point into, addresses moved to the graph's): real inputs that the
behaviour checks replay.
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
const captures = %CAPTURES%;
// A real input, for the behaviour checks to replay: the registers at entry and the memory pages they point into
// (and the stack's), read before the function runs.
function capture(address, ctx) {
  const regs = {};
  const pages = {};
  const page = (v) => {
    const base = v.and(ptr("0xfffffffffffff000"));
    const key = base.toString();
    if (key in pages) return;
    try { pages[key] = base.readByteArray(4096); } catch (e) { /* unreadable: left out */ }
  };
  for (const r of ["rdi", "rsi", "rdx", "rcx", "r8", "r9", "rsp", "rbx", "rbp", "r12", "r13", "r14", "r15"]) {
    regs[r] = ctx[r].toString();
  }
  for (const r of ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]) {
    if (Process.findRangeByAddress(ctx[r]) !== null) page(ctx[r]);
  }
  page(ctx.rsp);
  page(ctx.rsp.add(4096));
  const keys = Object.keys(pages);
  send({ capture: { address, regs, pages: keys } }, concat(keys.map((k) => pages[k])));
}
function concat(buffers) {
  const total = buffers.reduce((n, b) => n + b.byteLength, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const b of buffers) { out.set(new Uint8Array(b), at); at += b.byteLength; }
  return out.buffer;
}
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
        if (s.calls <= captures) capture("0x" + a.toString(16), this.context);
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
    probe = session.create_script(
        "rpc.exports = { base: () => { const m = Process.enumerateModules()[0]; return [m.base.toString(), m.size]; } };"
    )
    probe.load()
    base_text, module_size = probe.exports_sync.base()
    module_base = int(base_text, 16)
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
        .replace("%CAPTURES%", str(int(request.get("captures", 0))))
    )
    script = session.create_script(source)
    latest = {}
    final = {}

    out_captures = open(request["capture_file"], "w") if request.get("capture_file") else None

    def rebase(value):
        # Addresses inside the program's own image are moved to the graph's addresses (image at 0 when
        # position-independent); heap and stack addresses stay as they were.
        return value - delta if module_base <= value < module_base + module_size else value

    def on_message(message, data):
        payload = message.get("payload", {}) if message.get("type") == "send" else {}
        if "final" in payload:
            final.update(payload["final"])
            script.post({"type": "ack"})
        elif "capture" in payload and out_captures is not None:
            c = payload["capture"]
            pages = {}
            for i, key in enumerate(c["pages"]):
                raw = bytearray(data[i * 4096:(i + 1) * 4096])
                for at in range(0, 4096, 8):
                    word = int.from_bytes(raw[at:at + 8], "little")
                    moved = rebase(word)
                    if moved != word:
                        raw[at:at + 8] = moved.to_bytes(8, "little")
                pages[hex(rebase(int(key, 16)))] = raw.hex()
            regs = {r: hex(rebase(int(v, 16))) for r, v in c["regs"].items()}
            out_captures.write(json.dumps({"address": c["address"], "regs": regs, "pages": pages}) + "\n")

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
    if out_captures is not None:
        out_captures.close()
    print(json.dumps({"exit": state["exit"], "module_base": hex(module_base), "functions": final or latest}))


if __name__ == "__main__":
    main()
