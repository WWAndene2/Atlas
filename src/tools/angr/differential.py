"""Differential test of two machine-code versions of one function (x86-64): both run on the same concrete inputs.

Reads a JSON request (path in argv[1]), writes a JSON answer to stdout:
  request: {"original": {...}, "candidate": {...}, "max_steps": int, "buffer": int, "inputs": int, "seed": int}
  answer:  {"result": "same" | "different" | "inconclusive", "details": str, "counterexample"?: {...}}

Where the symbolic check (equivalence.py) gives up on loops whose count depends on the inputs, concrete inputs end
them. Pointer arguments are found as in equivalence.py, on a bounded symbolic run whose unfinished paths are
dropped (an argument dereferenced only past the bound is missed: it is then fed integers, and the run that reads
through it fails, counted as skipped). Integer arguments are drawn from edge values (0, 1, -1, the sign bit) and
small and full-width random numbers; buffers from random bytes. An input on which either version does not return
within max_steps basic blocks is skipped. "same" means no difference on the inputs run: evidence, not proof.
Callees are opaque functions as in equivalence.py (a fixed value per callee and call); calls through a register
or memory make the answer inconclusive. angr executes the code, never the host CPU.
"""

import json
import random
import sys

import angr
from angr import claripy

from equivalence import (
    ARG_REGS, BUF_BASE, BUF_STRIDE, SENTINEL, STACK, Inconclusive, callees, explore, hook_callees, initial_state, load
)

EDGES = [0, 1, 2, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0x8000000000000000]


def draw(rng):
    pick = rng.random()
    if pick < 0.3:
        return rng.choice(EDGES)
    if pick < 0.7:
        return rng.randrange(0, 64)
    if pick < 0.85:
        return rng.getrandbits(32)
    return rng.getrandbits(64)


def concrete_state(proj, pointers, buf_size, values, buffers, xmms):
    state = proj.factory.blank_state(
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    for i, reg in enumerate(ARG_REGS):
        if i in pointers:
            base = BUF_BASE + i * BUF_STRIDE
            state.memory.store(base, claripy.BVV(buffers[i], buf_size * 8))
            setattr(state.regs, reg, claripy.BVV(base, 64))
        else:
            setattr(state.regs, reg, claripy.BVV(values[i], 64))
    for i in range(4):
        setattr(state.regs, f"xmm{i}", claripy.BVV(xmms[i], 128))
    state.regs.rsp = STACK
    state.memory.store(STACK, claripy.BVV(SENTINEL, 64), endness="Iend_LE")
    state.globals["concrete"] = True
    return state


def outcome(proj, address, state, max_steps, buffers, buf_size, arity):
    try:
        finished, _ = explore(proj, address, state, max_steps, watch_symbolic=False)
    except Inconclusive:
        return None
    if len(finished) != 1:
        return None
    s = finished[0]
    ev = lambda e: s.solver.eval(e)  # noqa: E731
    return {
        "rax": ev(s.regs.rax),
        "xmm0": ev(s.regs.xmm0[63:0]),
        **{f"buf{(b - BUF_BASE) // BUF_STRIDE}": ev(s.memory.load(b, buf_size)) for b in buffers},
        # Calls made, with the callee's declared arguments (none compared when its arity is unknown).
        "calls": [(t, [ev(a) for a in args[: arity.get(t) or 0]]) for t, args in s.globals.get("calls", ())],
    }


def main():
    request = json.load(open(sys.argv[1]))
    max_steps = int(request.get("max_steps", 2000))
    buf_size = int(request.get("buffer", 256))
    inputs = int(request.get("inputs", 100))
    rng = random.Random(int(request.get("seed", 1)))
    orig, cand = request["original"], request["candidate"]
    arity = {int(k, 16): v for k, v in request.get("arity", {}).items()}
    p_orig, p_cand = load(orig), load(cand)
    try:
        targets_o, indirect_o = callees(p_orig, orig)
        targets_c, indirect_c = callees(p_cand, cand)
        if indirect_o or indirect_c:
            raise Inconclusive("a call through a register or memory: its callee cannot be known")
        if targets_c - targets_o:
            raise Inconclusive("the rewrite calls functions the original does not")
        hook_callees(p_orig, targets_o)
        hook_callees(p_cand, targets_c)
        probe, _ = initial_state(p_orig, set(), buf_size)
        _, pointers = explore(p_orig, orig["address"], probe, 300, watch_symbolic=True, allow_unfinished=True)
    except Inconclusive as reason:
        print(json.dumps({"result": "inconclusive", "details": str(reason)}))
        return
    buffers = [BUF_BASE + i * BUF_STRIDE for i in sorted(pointers)]
    ran = skipped = 0
    for _ in range(inputs):
        values = {i: draw(rng) for i in range(6)}
        bufs = {i: rng.getrandbits(buf_size * 8) for i in pointers}
        xmms = [rng.getrandbits(128) for _ in range(4)]
        a = outcome(p_orig, orig["address"], concrete_state(p_orig, pointers, buf_size, values, bufs, xmms), max_steps, buffers, buf_size, arity)
        b = outcome(p_cand, cand["address"], concrete_state(p_cand, pointers, buf_size, values, bufs, xmms), max_steps, buffers, buf_size, arity)
        if a is None or b is None:
            skipped += 1
            continue
        ran += 1
        if a != b:
            example = {f"arg{i}": hex(v) for i, v in values.items() if i not in pointers}
            differ = sorted(k for k in a if a[k] != b[k])
            print(json.dumps({"result": "different", "details": f"results differ in {', '.join(differ)}", "counterexample": example}))
            return
    if ran == 0:
        print(json.dumps({"result": "inconclusive", "details": f"no input ran to the end in both versions ({skipped} skipped)"}))
        return
    print(
        json.dumps(
            {
                "result": "same",
                "details": f"same results on {ran} inputs ({skipped} skipped)"
                + (f"; pointer arguments: {sorted(pointers)}" if pointers else ""),
            }
        )
    )


if __name__ == "__main__":
    main()
