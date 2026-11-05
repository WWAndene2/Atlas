"""Symbolic equivalence of two machine-code versions of one function (x86-64), with angr and Z3.

Reads a JSON request (path in argv[1]), writes a JSON answer to stdout:
  request: {"original": {"code": hex, "address": int}, "candidate": {"code": hex, "address": int},
            "max_steps": int, "buffer": int}
  answer:  {"result": "equivalent" | "different" | "inconclusive", "details": str, "counterexample"?: {...}}

Method. Both versions start from one initial state, so they read the same inputs:
1. Classification: a first run of the original with all six integer argument registers symbolic records which of
   them it dereferences (an address built from argument i means argument i is a pointer).
2. Comparison: pointer arguments hold the address of a symbolic buffer, the same buffer for both versions; the
   others stay symbolic integers. xmm0 to xmm3 are symbolic too (double arguments).
3. Every pair of finished paths (one of each version) is checked with Z3: an input under which both paths are taken
   and the results differ (rax, the low 64 bits of xmm0, or any buffer's final contents) makes the versions
   different, with that input as counterexample. No such input for any pair: equivalent.

Soundness limits, each answered inconclusive rather than equivalent: a function that calls others (the callees'
behaviour is not modelled), a path still running after max_steps basic blocks (loops whose count depends on the
inputs), an access through an address still symbolic after classification, or an angr error.
"""

import json
import sys

import angr
from angr import claripy  # angr 10 ships claripy inside it

ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
BUF_BASE = 0x10000000
BUF_STRIDE = 0x100000
STACK = 0x7FFF0000
SENTINEL = 0xDEAD0000


class Inconclusive(Exception):
    pass


def load(part):
    return angr.load_shellcode(bytes.fromhex(part["code"]), arch="amd64", load_address=part["address"])


def has_calls(proj, part):
    """Whether the function makes a call: the callee is not modelled, and its address differs between versions."""
    address, end = part["address"], part["address"] + len(part["code"]) // 2
    seen, todo = set(), [address]
    while todo:
        a = todo.pop()
        if a in seen or not (address <= a < end):
            continue
        seen.add(a)
        block = proj.factory.block(a)
        if block.size == 0:
            continue
        if block.vex.jumpkind == "Ijk_Call":
            return True
        for target in block.vex.constant_jump_targets:
            todo.append(target)
        todo.append(a + block.size)
    return False


def initial_state(proj, pointers, buf_size):
    state = proj.factory.blank_state(
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    args = {}
    for i, reg in enumerate(ARG_REGS):
        if i in pointers:
            base = BUF_BASE + i * BUF_STRIDE
            state.memory.store(base, claripy.BVS(f"buf{i}", buf_size * 8))
            setattr(state.regs, reg, claripy.BVV(base, 64))
        else:
            args[i] = claripy.BVS(f"arg{i}", 64)
            setattr(state.regs, reg, args[i])
    for i in range(4):
        setattr(state.regs, f"xmm{i}", claripy.BVS(f"xmm{i}", 128))
    state.regs.rsp = STACK
    state.memory.store(STACK, claripy.BVV(SENTINEL, 64), endness="Iend_LE")
    return state, args


def explore(proj, address, state, max_steps, watch_symbolic):
    """Runs from `address` until every path returns; records argument registers used as addresses if asked."""
    state = state.copy()
    state.regs.rip = address
    dereferenced = set()

    def on_access(s):
        addr = s.inspect.mem_read_address if s.inspect.mem_read_address is not None else s.inspect.mem_write_address
        # angr gives a concrete address as a plain int, a symbolic one as an expression.
        if addr is None or isinstance(addr, int) or not addr.symbolic:
            return
        names = addr.variables
        used = {int(n.split("_")[0][3:]) for n in names if n.startswith("arg")}
        if watch_symbolic:
            dereferenced.update(used)
        else:
            raise Inconclusive("an access through an address still symbolic after classification")

    state.inspect.b("mem_read", when=angr.BP_BEFORE, action=on_access)
    state.inspect.b("mem_write", when=angr.BP_BEFORE, action=on_access)
    simgr = proj.factory.simulation_manager(state)
    finished = []
    for _ in range(max_steps):
        if not simgr.active:
            break
        simgr.step()
        if simgr.errored:
            raise Inconclusive(f"angr error: {simgr.errored[0].error}")
        for s in list(simgr.active):
            if not s.regs.rip.symbolic and s.solver.eval(s.regs.rip) == SENTINEL:
                finished.append(s)
                simgr.active.remove(s)
    if simgr.active:
        raise Inconclusive(f"a path was still running after {max_steps} basic blocks")
    return finished, dereferenced


def main():
    request = json.load(open(sys.argv[1]))
    max_steps = int(request.get("max_steps", 300))
    buf_size = int(request.get("buffer", 256))
    orig, cand = request["original"], request["candidate"]
    p_orig, p_cand = load(orig), load(cand)
    try:
        if has_calls(p_orig, orig) or has_calls(p_cand, cand):
            raise Inconclusive("the function calls others: callees are not modelled")
        # 1. Classification on the original, every argument symbolic.
        probe, _ = initial_state(p_orig, set(), buf_size)
        _, pointers = explore(p_orig, orig["address"], probe, max_steps, watch_symbolic=True)
        # 2. Both versions from the same state.
        state, args = initial_state(p_orig, pointers, buf_size)
        paths_o, _ = explore(p_orig, orig["address"], state, max_steps, watch_symbolic=False)
        paths_c, _ = explore(p_cand, cand["address"], state, max_steps, watch_symbolic=False)
    except Inconclusive as reason:
        print(json.dumps({"result": "inconclusive", "details": str(reason)}))
        return
    if not paths_o or not paths_c:
        print(json.dumps({"result": "inconclusive", "details": "no path returned"}))
        return
    buffers = [BUF_BASE + i * BUF_STRIDE for i in sorted(pointers)]
    # 3. Any input taking a path of each version and making their results differ.
    solver = claripy.Solver()
    for so in paths_o:
        for sc in paths_c:
            differ = claripy.Or(
                so.regs.rax != sc.regs.rax,
                so.regs.xmm0[63:0] != sc.regs.xmm0[63:0],
                *[so.memory.load(b, buf_size) != sc.memory.load(b, buf_size) for b in buffers],
            )
            constraints = list(so.solver.constraints) + list(sc.solver.constraints) + [differ]
            if solver.satisfiable(extra_constraints=constraints):
                example = {f"arg{i}": hex(solver.eval(a, 1, extra_constraints=constraints)[0]) for i, a in args.items()}
                print(json.dumps({"result": "different", "details": "an input makes the results differ", "counterexample": example}))
                return
    print(
        json.dumps(
            {
                "result": "equivalent",
                "details": f"{len(paths_o)} x {len(paths_c)} path pairs, no input makes them differ"
                + (f"; pointer arguments: {sorted(pointers)}" if pointers else ""),
            }
        )
    )


if __name__ == "__main__":
    main()
