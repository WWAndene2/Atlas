"""Checks translations (lift.py) against the original binary by behaviour: each function is run twice on the same
generated inputs, once as compiled C (the translations of the whole program linked together, so calls go to
translated callees) and once as the original machine code in angr (the binary loaded whole, callees executed, its
imports modelled). Results compared: the return register and the bytes of every buffer behind a pointer argument.

argv[1]: request JSON {"binary": path, "arch": name, "c": path of the translations, "runtime": dir of atlas_lift.h,
                       "functions": [int], "inputs": int, "seed": int, "pointers": {"0x..": [arg indexes]}}
stdout: one JSON line per function: {"address", "result": "same" | "different" | "inconclusive", "details"}

x86-64 System V and ELF for now (argument registers, return register, stack). The translated side runs each call in
a forked child with an alarm, so a crash or a runaway loop costs one input; flat guest memory is a sparse mapping
holding the binary's loaded segments. An input that either side cannot finish (a callee not translated, an import
the C side cannot run, a step bound) is skipped; same means no difference on the inputs that ran: evidence, not proof.
"""

import ctypes
import json
import mmap
import os
import random
import signal
import struct
import subprocess
import sys
import tempfile

import angr
import archinfo
from angr import claripy

ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
STACK = 0x7FFF0000
SENTINEL = 0xDEAD0000
BUF_BASE = 0x10000000
BUF_STRIDE = 0x100000
BUF_SIZE = 256
MEM_SIZE = 1 << 32
EDGES = [0, 1, 2, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000]


def draw(rng):
    pick = rng.random()
    if pick < 0.3:
        return rng.choice(EDGES)
    if pick < 0.75:
        return rng.randrange(0, 64)
    return rng.getrandbits(32)


# C library functions the translated side runs on the host, by signature: the return kind then each argument's
# (p: a guest pointer, translated to and from host memory; i: an integer). Those that hand out memory (malloc) or
# jump (setjmp) are left out: their results would differ between the two sides by construction.
BRIDGE = {
    "strlen": "i p", "strcmp": "i pp", "strncmp": "i ppi", "memcmp": "i ppi", "strcoll": "i pp", "strspn": "i pp",
    "strcspn": "i pp", "memcpy": "p ppi", "memmove": "p ppi", "memset": "p pii", "strchr": "p pi", "strrchr": "p pi",
    "strcpy": "p pp", "strncpy": "p ppi", "strcat": "p pp", "strstr": "p pp", "strpbrk": "p pp", "memchr": "p pii",
    "toupper": "i i", "tolower": "i i", "abs": "i i", "labs": "i i",
}


def bridge_cases(imports):
    """C for each import of the bridge: its arguments taken from the guest registers, the result put back."""
    regs = ["REG(uint64_t, OFF_RDI)", "REG(uint64_t, OFF_RSI)", "REG(uint64_t, OFF_RDX)"]
    out = []
    for name, address in sorted(imports.items()):
        sig = BRIDGE.get(name)
        if sig is None:
            continue
        ret, params = sig.split(" ")
        args = ", ".join(f"(void *)ATLAS_HOST({regs[i]})" if k == "p" else f"(long){regs[i]}"
                         for i, k in enumerate(params))
        value = f"(uint64_t)((uint8_t *){name}({args}) - s->mem)" if ret == "p" else f"(uint64_t)(long){name}({args})"
        # x86-64: the call pushed a return address; the translated caller resumes after the call by itself, so the
        # bridge pops it, as the stub's ret would.
        out.append(f"    case {address:#x}ULL: REG(uint64_t, OFF_RAX) = {value}; REG(uint64_t, OFF_RSP) += 8; return;")
    return "\n".join(out)


def build(c_path, runtime, functions, work, imports, offsets):
    """The translations, the C library bridge and a dispatch table compiled into a shared library."""
    table = "\n".join(f"void fn_{a:x}(atlas_state *s);" for a in functions)
    cases = "\n".join(f"    case {a:#x}ULL: fn_{a:x}(s); return;" for a in functions)
    cases += "\n" + bridge_cases(imports)
    defines = "\n".join(f"#define OFF_{r.upper()} {offsets[r][0]}" for r in ("rdi", "rsi", "rdx", "rsp", "rax"))
    glue = f"""#include "atlas_lift.h"
#include <ctype.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
{defines}
{table}
jmp_buf atlas_escape;
uint64_t atlas_missing;
void atlas_call(atlas_state *s, uint64_t target) {{
  switch (target) {{
{cases}
    default: atlas_missing = target; longjmp(atlas_escape, 1);
  }}
}}
void atlas_trap(atlas_state *s, uint64_t at, int kind) {{ atlas_missing = at; longjmp(atlas_escape, 2); }}
int atlas_run(atlas_state *s, uint64_t entry) {{
  int r = setjmp(atlas_escape);
  if (r) return r;
  atlas_call(s, entry);
  return 0;
}}
"""
    open(os.path.join(work, "glue.c"), "w").write(glue)
    lib = os.path.join(work, "lifted.so")
    subprocess.run(["gcc", "-O1", "-w", "-shared", "-fPIC", f"-DATLAS_MEM_LIMIT={MEM_SIZE:#x}ULL", "-I", runtime, c_path, os.path.join(work, "glue.c"), "-o", lib],
                   check=True)
    return lib


def load_segments(path, mem):
    with open(path, "rb") as f:
        data = f.read()
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
        if p_type == 1 and p_vaddr + p_memsz < MEM_SIZE:
            mem[p_vaddr:p_vaddr + p_filesz] = data[p_offset:p_offset + p_filesz]


def run_lifted(lib, state, offsets, mem, entry, args, buffers, timeout=2):
    """Runs one call of the translation in a forked child; returns (rax, buffers) or None."""
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read)
        signal.alarm(timeout)
        for i, reg in enumerate(ARG_REGS):
            off, _ = offsets[reg]
            struct.pack_into("<Q", state.r, off, args[i])
        for base, content in buffers.items():
            mem[base:base + BUF_SIZE] = content
        struct.pack_into("<Q", state.r, offsets["rsp"][0], STACK)
        mem[STACK:STACK + 8] = struct.pack("<Q", SENTINEL)
        code = lib.atlas_run(ctypes.byref(state), ctypes.c_uint64(entry))
        missing = ctypes.c_uint64.in_dll(lib, "atlas_missing").value
        out = {"skip": ("C side: call to untranslated " if code == 1 else "C side: trap at ") + hex(missing)}
        if code == 0:
            rax = struct.unpack_from("<Q", state.r, offsets["rax"][0])[0]
            out = {"rax": rax, **{hex(b): mem[b:b + BUF_SIZE].hex() for b in buffers}}
        os.write(write, json.dumps(out).encode())
        os._exit(0)
    os.close(write)
    chunks = []
    while True:
        chunk = os.read(read, 1 << 16)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(read)
    _, status = os.waitpid(pid, 0)
    try:
        out = json.loads(b"".join(chunks) or b"null")
    except ValueError:
        out = None
    if out is None:
        sig = os.WTERMSIG(status) if os.WIFSIGNALED(status) else 0
        return {"skip": "C side: " + ("out of time" if sig == signal.SIGALRM else f"crashed (signal {sig})")}
    return out


def run_original(proj, entry, args, buffers, max_steps=4000):
    state = proj.factory.blank_state(addr=entry, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                                               angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    for i, reg in enumerate(ARG_REGS):
        setattr(state.regs, reg, claripy.BVV(args[i], 64))
    for base, content in buffers.items():
        state.memory.store(base, content)
    state.regs.rsp = STACK
    state.memory.store(STACK, claripy.BVV(SENTINEL, 64), endness="Iend_LE")
    simgr = proj.factory.simulation_manager(state)
    for _ in range(max_steps):
        simgr.step()
        if simgr.errored:
            return {"skip": f"original: angr error {str(simgr.errored[0].error)[:80]}"}
        if len(simgr.active) != 1:
            return {"skip": f"original: {len(simgr.active)} paths (a branch on unknown data)"}
        s = simgr.active[0]
        if not s.regs.rip.symbolic and s.solver.eval(s.regs.rip) == SENTINEL:
            return {"rax": s.solver.eval(s.regs.rax),
                    **{hex(b): s.solver.eval(s.memory.load(b, BUF_SIZE)).to_bytes(BUF_SIZE, "big").hex() for b in buffers}}
    return {"skip": "original: step bound"}


def main():
    request = json.load(open(sys.argv[1]))
    arch = archinfo.arch_from_id(request["arch"])
    offsets = {r: arch.registers[r] for r in ARG_REGS + ["rsp", "rax"]}
    functions = [int(a) for a in request["functions"]]
    translated = request.get("translated", functions)
    work = tempfile.mkdtemp(prefix="atlas-lifted-")
    proj = angr.Project(request["binary"], auto_load_libs=False, main_opts={"base_addr": 0})
    imports = dict(proj.loader.main_object.plt)
    lib = ctypes.CDLL(build(request["c"], request["runtime"], translated, work, imports, offsets))
    lib.atlas_run.restype = ctypes.c_int

    class State(ctypes.Structure):
        _fields_ = [("r", ctypes.c_uint8 * 4096), ("mem", ctypes.c_void_p)]

    raw = mmap.mmap(-1, MEM_SIZE, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | getattr(mmap, "MAP_NORESERVE", 0))
    load_segments(request["binary"], raw)
    state = State()
    state.mem = ctypes.addressof(ctypes.c_uint8.from_buffer(raw))
    rng = random.Random(int(request.get("seed", 1)))
    pointers = {int(k, 16): v for k, v in request.get("pointers", {}).items()}
    for entry in functions:
        ran = skipped = 0
        reasons = {}
        verdict = None
        for _ in range(int(request.get("inputs", 10))):
            args = [draw(rng) for _ in ARG_REGS]
            buffers = {}
            for i in pointers.get(entry, []):
                base = BUF_BASE + i * BUF_STRIDE
                args[i] = base
                buffers[base] = bytes(rng.getrandbits(8) for _ in range(BUF_SIZE))
            a = run_lifted(lib, state, offsets, raw, entry, args, buffers)
            b = run_original(proj, entry, args, buffers) if "skip" not in a else {}
            reason = a.get("skip") or b.get("skip")
            if reason is not None:
                skipped += 1
                reasons[reason] = reasons.get(reason, 0) + 1
                continue
            ran += 1
            if a != b:
                differ = sorted(k for k in a if a[k] != b[k])
                verdict = {"result": "different", "details": f"differ in {', '.join(differ)} for {[hex(x) for x in args]}"}
                break
        if verdict is None:
            verdict = ({"result": "same", "details": f"same results on {ran} inputs ({skipped} skipped)"} if ran
                       else {"result": "inconclusive", "details": f"no input ran on both sides ({skipped} skipped)"})
        if reasons:
            verdict["skipped"] = reasons
        print(json.dumps({"address": hex(entry), **verdict}), flush=True)


if __name__ == "__main__":
    main()
