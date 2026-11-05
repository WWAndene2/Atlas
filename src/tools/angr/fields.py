"""Field accesses through each pointer argument of a function, by symbolic execution of the whole binary.

argv[1]: request JSON {"binary": path, "functions": [int], "max_steps": int, "max_states": int, "seconds": float}
stdout: one JSON line per function, as it is done:
        {"address": "0x..", "args": {"0": [{"offset": int, "size": int, "read": bool, "write": bool}]},
         "complete": bool, "error"?: str}
(a function stuck in the solver past every bound loses only itself: the caller keeps the lines already written)

Each function starts from a state where the six integer argument registers (System V x86-64) hold distinct symbolic
values. A memory access whose address is argument i plus a constant is a field of what argument i points to, at that
offset and width; callees are followed (a field read in a helper is still a field), imports run as angr's models.
Addresses are the binary's own (angr maps a position-independent binary at 0 here, as the graph does). Exploration
is bounded (blocks, live paths, time): `complete` says whether every path returned within the bounds; fields from an
incomplete run are still real accesses, only possibly not all of them. The target is executed by angr, never natively.
"""

import json
import signal
import sys
import time

import angr
from angr import claripy

ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]


def base_plus_constant(expr, base):
    """The constant c when expr is base + c (sums and differences of constants), else None."""
    terms, constant = [], 0

    def walk(e, sign):
        nonlocal constant
        if e.op == "BVV":
            constant += sign * e.args[0]
        elif e.op == "__add__":
            for a in e.args:
                walk(a, sign)
        elif e.op == "__sub__":
            walk(e.args[0], sign)
            for a in e.args[1:]:
                walk(a, -sign)
        else:
            terms.append((e, sign))

    walk(expr, 1)
    if len(terms) == 1 and terms[0][1] == 1 and terms[0][0] is base or (len(terms) == 1 and terms[0][1] == 1 and terms[0][0].identical(base)):
        constant %= 1 << 64
        return constant - (1 << 64) if constant >= 1 << 63 else constant
    return None


def fields_of(proj, address, max_steps, max_states, seconds):
    args = [claripy.BVS(f"arg{i}", 64) for i in range(6)]
    state = proj.factory.call_state(
        address,
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS},
    )
    # Set directly: without a known prototype angr would pass none of them.
    for reg, value in zip(ARG_REGS, args):
        setattr(state.regs, reg, value)
    found = {}

    def on_access(s, write):
        addr = s.inspect.attrs.mem_write_address if write else s.inspect.attrs.mem_read_address
        size = s.inspect.attrs.mem_write_length if write else s.inspect.attrs.mem_read_length
        if addr is None or isinstance(addr, int) or not addr.symbolic:
            return
        names = list(addr.variables)
        if len(names) != 1 or not names[0].startswith("arg"):
            return
        i = int(names[0][3:].split("_")[0])
        off = base_plus_constant(addr, args[i])
        if off is None:
            return
        n = size if isinstance(size, int) else (s.solver.eval(size) if size is not None and not size.symbolic else 0)
        key = (i, off, n)
        entry = found.setdefault(key, {"offset": off, "size": n, "read": False, "write": False})
        entry["write" if write else "read"] = True

    state.inspect.b("mem_read", when=angr.BP_BEFORE, action=lambda s: on_access(s, False))
    state.inspect.b("mem_write", when=angr.BP_BEFORE, action=lambda s: on_access(s, True))
    simgr = proj.factory.simulation_manager(state)
    start = time.monotonic()
    for _ in range(max_steps):
        if not simgr.active or time.monotonic() - start > seconds:
            break
        simgr.step()
        # Paths that leave mapped code or loop on symbolic data are dropped; too many live paths are cut.
        simgr.drop(stash="errored")
        if len(simgr.active) > max_states:
            simgr.split(from_stash="active", to_stash="dropped", limit=max_states)
    out = {}
    for (i, _, _), entry in sorted(found.items()):
        out.setdefault(str(i), []).append(entry)
    return {"args": out, "complete": not simgr.active and not simgr.stashes.get("dropped")}


class OutOfTime(Exception):
    pass


def on_alarm(_signum, _frame):
    raise OutOfTime()


def main():
    # One solver call can outlast the time bound checked between steps: an alarm stops the function regardless.
    signal.signal(signal.SIGALRM, on_alarm)
    request = json.load(open(sys.argv[1]))
    proj = angr.Project(request["binary"], auto_load_libs=False, main_opts={"base_addr": 0} if request.get("pie") else {})
    for address in request["functions"]:
        signal.alarm(int(float(request.get("seconds", 10)) * 3) + 1)
        try:
            result = fields_of(
                proj,
                address,
                int(request.get("max_steps", 60)),
                int(request.get("max_states", 8)),
                float(request.get("seconds", 10)),
            )
        except OutOfTime:
            result = {"args": {}, "complete": False, "error": "out of time"}
        except Exception as error:
            result = {"args": {}, "complete": False, "error": f"{type(error).__name__}: {error}"[:200]}
        finally:
            signal.alarm(0)
        print(json.dumps({"address": hex(address), **result}), flush=True)


if __name__ == "__main__":
    main()
