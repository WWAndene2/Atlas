"""Symbolic equivalence of two machine-code versions of one function (x86-64), with angr and Z3.

Reads a JSON request (path in argv[1]), writes a JSON answer to stdout:
  request: {"original": {"code": hex, "address": int}, "candidate": {"code": hex, "address": int},
            "max_steps": int, "buffer": int, "arity"?: {"0x<callee>": int | null}}
  answer:  {"result": "equivalent" | "different" | "inconclusive", "details": str, "counterexample"?: {...}}

Method. Both versions start from one initial state, so they read the same inputs:
1. Classification: a first run of the original with all six integer argument registers symbolic records which of
   them it dereferences (an address built from argument i means argument i is a pointer).
2. Comparison: pointer arguments hold the address of a symbolic buffer, the same buffer for both versions; the
   others stay symbolic integers. xmm0 to xmm3 are symbolic too (double arguments).
3. Every pair of finished paths (one of each version) is checked with Z3: an input under which both paths are taken
   and the results differ (rax, the low 64 bits of xmm0, or any buffer's final contents) makes the versions
   different, with that input as counterexample. No such input for any pair: equivalent.

Calls: each callee (a constant target outside the function; the candidate's calls are linked by Atlas to the
original's callees beforehand) is replaced by an opaque function whose k-th call returns the same fresh value in
both versions; the two paths must make the same calls, with the same arguments up to each callee's arity. Memory a
callee would write is not modelled (both versions see it unchanged), which is the method's main assumption.

Soundness limits, each answered inconclusive rather than equivalent: a call through a register or memory, a call
whose arguments cannot be compared (unknown arity), a callee of the rewrite that the original does not call, a
path still running after max_steps basic blocks (loops whose count depends on the inputs), an access through an address still symbolic after classification, or an angr error.
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


def callees(proj, part):
    """The functions the code calls or tail-jumps to (constant targets outside its own bytes), and whether it also
    makes a call through a register or memory, whose callee cannot be known."""
    address, end = part["address"], part["address"] + len(part["code"]) // 2
    seen, todo, targets, indirect = set(), [address], set(), False
    while todo:
        a = todo.pop()
        if a in seen or not (address <= a < end):
            continue
        seen.add(a)
        block = proj.factory.block(a)
        if block.size == 0:
            continue
        constant = list(block.vex.constant_jump_targets)
        if block.vex.jumpkind == "Ijk_Call" and not constant:
            indirect = True
        for target in constant:
            if address <= target < end:
                todo.append(target)
            else:
                targets.add(target)
        if block.vex.jumpkind == "Ijk_Call":
            todo.append(a + block.size)
        elif block.vex.jumpkind != "Ijk_Ret":
            todo.append(a + block.size)
    return targets, indirect


def call_differences(so, sc, arity, unchecked):
    """Conditions under which the two paths' calls differ: another callee or count, or another argument among the
    callee's declared ones (arity; a callee of unknown arity has its arguments left unchecked, noted in unchecked)."""
    calls_o, calls_c = so.globals.get("calls", ()), sc.globals.get("calls", ())
    if [t for t, _ in calls_o] != [t for t, _ in calls_c]:
        return [claripy.true()]
    out = []
    for (t, args_o), (_, args_c) in zip(calls_o, calls_c):
        n = arity.get(t)
        if n is None:
            unchecked.add(t)
            continue
        out += [args_o[i] != args_c[i] for i in range(min(n, len(ARG_REGS)))]
    return out


class Opaque(angr.SimProcedure):
    """A callee not executed: its k-th call returns a value named after the callee and k, so both versions get the
    same value from the same call, and the call (callee and arguments) is logged to be compared between versions.
    Memory the callee would write is not modelled: both versions see memory as they left it."""

    def run(self):
        target = self.state.addr
        log = list(self.state.globals.get("calls", ()))
        k = sum(1 for t, _ in log if t == target)
        args = tuple(getattr(self.state.regs, r) for r in ARG_REGS)
        log.append((target, args))
        self.state.globals["calls"] = tuple(log)
        if self.state.globals.get("concrete"):
            # Concrete runs (differential.py): a fixed value derived from the callee and k, the same in both.
            return claripy.BVV(hash((target, k)) & 0xFFFFFFFFFFFFFFFF, 64)
        return claripy.BVS(f"ret_{target:x}_{k}", 64, explicit_name=True)


def hook_callees(proj, targets):
    for t in targets:
        proj.hook(t, Opaque())


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


def explore(proj, address, state, max_steps, watch_symbolic, allow_unfinished=False):
    """Runs from `address` until every path returns; records argument registers used as addresses if asked.
    With allow_unfinished, paths still running after max_steps are dropped instead of making the run inconclusive."""
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
    if simgr.active and not allow_unfinished:
        raise Inconclusive(f"a path was still running after {max_steps} basic blocks")
    return finished, dereferenced


def main():
    request = json.load(open(sys.argv[1]))
    max_steps = int(request.get("max_steps", 300))
    buf_size = int(request.get("buffer", 256))
    orig, cand = request["original"], request["candidate"]
    p_orig, p_cand = load(orig), load(cand)
    try:
        targets_o, indirect_o = callees(p_orig, orig)
        targets_c, indirect_c = callees(p_cand, cand)
        if indirect_o or indirect_c:
            raise Inconclusive("a call through a register or memory: its callee cannot be known")
        unknown = targets_c - targets_o
        if unknown:
            # The candidate's calls were linked to the original's callees (atlas); one elsewhere was not resolved.
            raise Inconclusive(f"the rewrite calls functions the original does not: {sorted(hex(t) for t in unknown)}")
        hook_callees(p_orig, targets_o)
        hook_callees(p_cand, targets_c)
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
    arity = {int(k, 16): v for k, v in request.get("arity", {}).items()}
    unchecked = set()
    solver = claripy.Solver()
    for so in paths_o:
        for sc in paths_c:
            differ = claripy.Or(
                *call_differences(so, sc, arity, unchecked),
                so.regs.rax != sc.regs.rax,
                so.regs.xmm0[63:0] != sc.regs.xmm0[63:0],
                *[so.memory.load(b, buf_size) != sc.memory.load(b, buf_size) for b in buffers],
            )
            constraints = list(so.solver.constraints) + list(sc.solver.constraints) + [differ]
            if solver.satisfiable(extra_constraints=constraints):
                example = {f"arg{i}": hex(solver.eval(a, 1, extra_constraints=constraints)[0]) for i, a in args.items()}
                print(json.dumps({"result": "different", "details": "an input makes the results differ", "counterexample": example}))
                return
    if unchecked:
        # Everything else agrees, but a call's arguments could not be compared: no proof.
        print(json.dumps({"result": "inconclusive", "details": "no difference found, but the arguments of calls to "
                          + ", ".join(sorted(hex(t) for t in unchecked)) + " are unchecked (their arity is unknown)"}))
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
