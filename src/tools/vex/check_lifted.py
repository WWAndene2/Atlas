"""Checks translations (lift.py) against the original binary by behaviour: each function is run twice on the same
inputs, once as compiled C (the whole program's translations linked together, calls through a dispatch table) and
once as the original machine code in angr (the binary loaded whole, callees executed, imports modelled). Compared:
the return register and every memory page of the input after the call.

argv[1]: request JSON {"binary": path, "arch": name, "c": translations, "runtime": dir of atlas_lift.h,
                       "functions": [int], "translated": [int], "inputs": int, "seed": int,
                       "pointers"?: {"0x..": [arg indexes]}, "captures"?: path}
stdout: one JSON line per function: {"address", "result": "same" | "different" | "inconclusive", "details",
                                     "skipped"?: {reason: count}}

An input is registers and 4 KiB memory pages. Real ones come from captures (atlas trace with captures: the registers
and the pages they point into, at entry, while the program ran); without them, inputs are generated (edge, small
and random integers; a random page behind each pointer argument). Memory is paged on both sides, holding the
binary's loaded segments and the input's pages; the C side runs each input in a forked child (a crash or a runaway
loop costs one input). C library calls the C side meets are run by small guest-memory versions of the common ones.
x86-64 System V and ELF for now. Same means no difference on the inputs that ran: evidence, not proof.
"""

import ctypes
import json
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
SAVED = ["rbx", "rbp", "r12", "r13", "r14", "r15"]
STACK = 0x7FFF0000
RETURN = 0xDEAD0000
BUF_BASE = 0x10000000
BUF_STRIDE = 0x100000
PAGE = 4096
EDGES = [0, 1, 2, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000]

# Guest-memory versions of common C library functions: what the C side runs for an import of that name.
BRIDGE = {
    "strlen": "uint64_t n = 0; while (LOAD8(A0 + n)) n++; RET(n);",
    "strcmp": "uint64_t i = 0; for (;; i++) { uint8_t a = LOAD8(A0 + i), b = LOAD8(A1 + i); "
              "if (a != b || !a) RET((uint64_t)(int64_t)((int)a - (int)b)); }",
    "strcoll": "uint64_t i = 0; for (;; i++) { uint8_t a = LOAD8(A0 + i), b = LOAD8(A1 + i); "
               "if (a != b || !a) RET((uint64_t)(int64_t)((int)a - (int)b)); }",
    "strncmp": "for (uint64_t i = 0; i < A2; i++) { uint8_t a = LOAD8(A0 + i), b = LOAD8(A1 + i); "
               "if (a != b || !a) RET((uint64_t)(int64_t)((int)a - (int)b)); } RET(0);",
    "memcmp": "for (uint64_t i = 0; i < A2; i++) { uint8_t a = LOAD8(A0 + i), b = LOAD8(A1 + i); "
              "if (a != b) RET((uint64_t)(int64_t)((int)a - (int)b)); } RET(0);",
    "memcpy": "for (uint64_t i = 0; i < A2; i++) STORE8(A0 + i, LOAD8(A1 + i)); RET(A0);",
    "memmove": "if (A0 < A1) { for (uint64_t i = 0; i < A2; i++) STORE8(A0 + i, LOAD8(A1 + i)); } "
               "else { for (uint64_t i = A2; i > 0; i--) STORE8(A0 + i - 1, LOAD8(A1 + i - 1)); } RET(A0);",
    "memset": "for (uint64_t i = 0; i < A2; i++) STORE8(A0 + i, (uint8_t)A1); RET(A0);",
    "memchr": "for (uint64_t i = 0; i < A2; i++) if (LOAD8(A0 + i) == (uint8_t)A1) RET(A0 + i); RET(0);",
    "strchr": "for (uint64_t i = 0;; i++) { uint8_t c = LOAD8(A0 + i); if (c == (uint8_t)A1) RET(A0 + i); "
              "if (!c) RET(0); }",
    "strrchr": "uint64_t r = 0; for (uint64_t i = 0;; i++) { uint8_t c = LOAD8(A0 + i); "
               "if (c == (uint8_t)A1) r = A0 + i; if (!c) RET(r); }",
    "strcpy": "uint64_t i = 0; uint8_t c; do { c = LOAD8(A1 + i); STORE8(A0 + i, c); i++; } while (c); RET(A0);",
    "toupper": "RET((A0 >= 'a' && A0 <= 'z') ? A0 - 32 : A0);",
    "tolower": "RET((A0 >= 'A' && A0 <= 'Z') ? A0 + 32 : A0);",
    "abs": "RET((uint64_t)(int64_t)abs((int)A0));",
    "labs": "RET((uint64_t)labs((long)A0));",
}


def glue(functions, imports, offsets):
    regs = {r: offsets[r][0] for r in ARG_REGS + ["rsp", "rax"]}
    decls = "\n".join(f"void fn_{a:x}(atlas_state *s);" for a in functions)
    cases = [f"    case {a:#x}ULL: fn_{a:x}(s); return;" for a in functions]
    bridges = []
    for name, address in sorted(imports.items()):
        body = BRIDGE.get(name)
        if body is None:
            continue
        bridges.append(f"static void bridge_{name}(atlas_state *s) {{ {body} }}")
        # The translated caller resumes after the call itself; the bridge pops the return address, as ret would.
        cases.append(f"    case {address:#x}ULL: bridge_{name}(s); REG(uint64_t, {regs['rsp']}) += 8; return;")
    return f"""#define ATLAS_PAGED
#include "atlas_lift.h"
#include <setjmp.h>
#include <stdlib.h>
{decls}
#define A0 REG(uint64_t, {regs['rdi']})
#define A1 REG(uint64_t, {regs['rsi']})
#define A2 REG(uint64_t, {regs['rdx']})
#define RET(v) do {{ REG(uint64_t, {regs['rax']}) = (uint64_t)(v); return; }} while (0)
/* Pages: an open-addressing table from page number to a 4 KiB block, made on first use. */
#define SLOTS (1 << 20)
static uint64_t keys[SLOTS];
static uint8_t *blocks[SLOTS];
uint8_t *atlas_page(atlas_state *s, uint64_t a) {{
  uint64_t key = (a >> 12) + 1, i = (key * 0x9E3779B97F4A7C15ULL) >> 44;
  while (keys[i] && keys[i] != key) i = (i + 1) & (SLOTS - 1);
  if (!keys[i]) {{ keys[i] = key; blocks[i] = calloc(1, 4096); }}
  return blocks[i];
}}
void atlas_poke(atlas_state *s, uint64_t a, const uint8_t *src, uint64_t n) {{
  for (uint64_t i = 0; i < n; i++) atlas_page(s, a + i)[(a + i) & 0xfff] = src[i];
}}
void atlas_peek(atlas_state *s, uint64_t a, uint8_t *dst, uint64_t n) {{
  for (uint64_t i = 0; i < n; i++) dst[i] = atlas_page(s, a + i)[(a + i) & 0xfff];
}}
{chr(10).join(bridges)}
jmp_buf atlas_escape;
uint64_t atlas_missing;
void atlas_call(atlas_state *s, uint64_t target) {{
  switch (target) {{
{chr(10).join(cases)}
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


def build(c_path, runtime, functions, imports, offsets, work):
    open(os.path.join(work, "glue.c"), "w").write(glue(functions, imports, offsets))
    lib = os.path.join(work, "lifted.so")
    subprocess.run(["gcc", "-O1", "-w", "-shared", "-fPIC", "-DATLAS_PAGED", "-I", runtime, c_path,
                    os.path.join(work, "glue.c"), "-o", lib], check=True)
    return lib


def segments(path):
    with open(path, "rb") as f:
        data = f.read()
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
        if p_type == 1:
            yield p_vaddr, data[p_offset:p_offset + p_filesz]


def generated(rng, entry, pointers):
    """An input made up: integers in the argument registers, a random page behind each pointer argument, and a
    stack whose top holds a return address no code has."""
    regs = {r: rng.choice(EDGES) if rng.random() < 0.3 else rng.randrange(0, 64) if rng.random() < 0.6
            else rng.getrandbits(32) for r in ARG_REGS}
    pages = {}
    for i in pointers.get(entry, []):
        base = BUF_BASE + i * BUF_STRIDE
        regs[ARG_REGS[i]] = base
        pages[base] = bytes(rng.getrandbits(8) for _ in range(PAGE))
    regs["rsp"] = STACK + 0x800
    stack = bytearray(PAGE)
    struct.pack_into("<Q", stack, 0x800, RETURN)
    pages[STACK] = bytes(stack)
    return {"regs": regs, "pages": pages}


def run_c(lib, State, offsets, entry, case, timeout=2):
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read)
        signal.alarm(timeout)
        state = State()
        for base, content in case["pages"].items():
            lib.atlas_poke(ctypes.byref(state), ctypes.c_uint64(base), content, len(content))
        for r, v in case["regs"].items():
            if r in offsets:
                struct.pack_into("<Q", state.r, offsets[r][0], v)
        code = lib.atlas_run(ctypes.byref(state), ctypes.c_uint64(entry))
        if code == 0:
            out = {"rax": struct.unpack_from("<Q", state.r, offsets["rax"][0])[0]}
            for base in case["pages"]:
                buf = ctypes.create_string_buffer(PAGE)
                lib.atlas_peek(ctypes.byref(state), ctypes.c_uint64(base), buf, PAGE)
                out[hex(base)] = buf.raw.hex()
        else:
            missing = ctypes.c_uint64.in_dll(lib, "atlas_missing").value
            out = {"skip": ("C side: call to untranslated " if code == 1 else "C side: trap at ") + hex(missing)}
        os.write(write, json.dumps(out).encode())
        os._exit(0)
    os.close(write)
    chunks = []
    while True:
        chunk = os.read(read, 1 << 20)
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


def run_original(proj, entry, case, max_steps=4000):
    state = proj.factory.blank_state(addr=entry, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                                               angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    for base, content in case["pages"].items():
        state.memory.store(base, content)
    for r, v in case["regs"].items():
        setattr(state.regs, r, claripy.BVV(v, 64))
    rsp = case["regs"]["rsp"]
    ret = int.from_bytes(case["pages"][rsp & ~0xFFF][rsp & 0xFFF:(rsp & 0xFFF) + 8], "little") \
        if (rsp & ~0xFFF) in case["pages"] and (rsp & 0xFFF) <= PAGE - 8 else None
    if ret is None:
        return {"skip": "input: no stack page"}
    simgr = proj.factory.simulation_manager(state)
    for _ in range(max_steps):
        simgr.step()
        if simgr.errored:
            return {"skip": f"original: angr error {str(simgr.errored[0].error)[:60]}"}
        if len(simgr.active) != 1:
            return {"skip": f"original: {len(simgr.active)} paths"}
        s = simgr.active[0]
        # Returned: back at the return address with the stack popped.
        if not s.regs.rip.symbolic and s.solver.eval(s.regs.rip) == ret and s.solver.eval(s.regs.rsp) == rsp + 8:
            out = {"rax": s.solver.eval(s.regs.rax)}
            for base in case["pages"]:
                out[hex(base)] = s.solver.eval(s.memory.load(base, PAGE)).to_bytes(PAGE, "big").hex()
            return out
    return {"skip": "original: step bound"}


def live(case, out):
    """Memory below the stack pointer the caller gets back is dead after the return (callee frames, scratch the two
    sides leave differently): blanked before comparing."""
    end = case["regs"]["rsp"] + 8
    for base in case["pages"]:
        key = hex(base)
        if key in out and base < end:
            cut = min(PAGE, end - base)
            out[key] = "00" * cut + out[key][2 * cut:]
    return out


def load_captures(path):
    by = {}
    for line in open(path):
        c = json.loads(line)
        case = {"regs": {r: int(v, 16) for r, v in c["regs"].items()},
                "pages": {int(k, 16): bytes.fromhex(v) for k, v in c["pages"].items()}}
        by.setdefault(int(c["address"], 16), []).append(case)
    return by


def main():
    request = json.load(open(sys.argv[1]))
    arch = archinfo.arch_from_id(request["arch"])
    offsets = {r: arch.registers[r] for r in ARG_REGS + SAVED + ["rsp", "rax"]}
    functions = [int(a) for a in request["functions"]]
    translated = [int(a) for a in request.get("translated", functions)]
    proj = angr.Project(request["binary"], auto_load_libs=False, main_opts={"base_addr": 0})
    work = tempfile.mkdtemp(prefix="atlas-lifted-")
    lib = ctypes.CDLL(build(request["c"], request["runtime"], translated, dict(proj.loader.main_object.plt), offsets, work))
    lib.atlas_run.restype = ctypes.c_int

    class State(ctypes.Structure):
        _fields_ = [("r", ctypes.c_uint8 * 4096), ("mem", ctypes.c_void_p)]

    # The binary's segments, loaded once in this process: each forked child starts from them.
    loader = State()
    for vaddr, content in segments(request["binary"]):
        lib.atlas_poke(ctypes.byref(loader), ctypes.c_uint64(vaddr), content, len(content))
    captures = load_captures(request["captures"]) if request.get("captures") else {}
    rng = random.Random(int(request.get("seed", 1)))
    pointers = {int(k, 16): v for k, v in request.get("pointers", {}).items()}
    for entry in functions:
        cases = captures.get(entry) or [generated(rng, entry, pointers) for _ in range(int(request.get("inputs", 6)))]
        ran, reasons, verdict = 0, {}, None
        for case in cases:
            a = run_c(lib, State, offsets, entry, case)
            b = run_original(proj, entry, case) if "skip" not in a else {}
            reason = a.get("skip") or b.get("skip")
            if reason is not None:
                reasons[reason] = reasons.get(reason, 0) + 1
                continue
            ran += 1
            a, b = live(case, a), live(case, b)
            if a != b:
                differ = sorted(k for k in a if a[k] != b.get(k))
                verdict = {"result": "different", "details": f"differ in {', '.join(differ)}"}
                break
        if verdict is None:
            verdict = ({"result": "same", "details": f"same results on {ran} {'real' if entry in captures else 'generated'} inputs"}
                       if ran else {"result": "inconclusive", "details": "no input ran on both sides"})
        if reasons:
            verdict["skipped"] = reasons
        print(json.dumps({"address": hex(entry), **verdict}), flush=True)


if __name__ == "__main__":
    main()
