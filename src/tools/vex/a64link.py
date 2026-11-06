"""Links an AArch64 Linux program's translations (lift.py) into an executable for an x86-64 Linux host: an Android
app's native code, or any AArch64 program built against the C library, run on a PC.

Request, a JSON file named on the command line: {"binary": path of the ELF (read again when the program starts),
"lifted": [paths of the translations' C], "translated": [graph addresses], "base": where a position-independent
image is mapped, "runtime": directory of atlas_lift.h, "out": path of the executable}
stdout: {"executable": path, "imports": int, "own": [data imports the program provides itself]}
An import the host lacks stops the program when it is called, with its name.

Both are LP64 Linux with the same C library, so this follows link.py: identity memory (the image mapped at base, a
guest pointer is a host pointer), relocations applied as the dynamic loader would, and the host's C library called
for each import. Only the calling convention differs, and both give integer and floating-point arguments their own
registers in order: the guest's x0-x5 become rdi..r9, x6, x7 and the stack arguments the host's stack arguments,
d0-d7 xmm0-7 (variadic ones too: AArch64 Linux passes them as named ones); x0, x1 and d0, d1 take rax, rdx and
xmm0, xmm1 back. A call leaves its return address in x30, so nothing is popped. A guest function handed to qsort,
bsearch or an exit handler registration is replaced by a host stub bound to it, which enters the guest with the
conversion the other way; signal and sigaction install a guest handler the same way (the guest state saved around it,
so a signal arriving in the middle of translated code leaves that code as it was). Data the host's C library does not export
(AArch64's __stack_chk_guard, a global there) is a variable of the program. setjmp and longjmp run in the
translated caller's frame (jumps.py, AArch64 registers). The program starts at the entry, whose call to
__libc_start_main runs the translated main.
"""

import json
import subprocess
import sys

import archinfo
import cle

from jumps import A64_ARGS, A64_FRAME, A64_SAVED, LONGJMP_NAMES, SETJMP_HEADER, SETJMP_NAMES, jumps_c
from link import ENTER_GUEST, TRAMPOLINE

# Imports that call a function the guest passes them (the argument's position): qsort's and bsearch's comparison,
# and the handlers run at exit (glibc's atexit is linked into the program and registers through __cxa_atexit).
CALLBACK_ARGS = {"qsort": 3, "bsearch": 4, "atexit": 0, "__cxa_atexit": 0, "on_exit": 0,
                 "signal": 1, "bsd_signal": 1, "sysv_signal": 1, "__sysv_signal": 1}
# Those that return the handler they replace: a stub there is turned back into the guest's handler.
RETURNS_HANDLER = {"signal", "bsd_signal", "sysv_signal", "__sysv_signal"}
CALLBACK_SLOTS = 64

# Data imports the host's C library does not have, and their initial value.
OWN_DATA = {"__stack_chk_guard": 0x2F8D6E1A5C4B3907}


def c_string(text):
    """A C string literal for any path, every byte escaped in octal."""
    return '"' + "".join(f"\\{b:03o}" for b in text.encode()) + '"'


def main():
    request = json.load(open(sys.argv[1]))
    arch = archinfo.arch_from_id("AARCH64")
    off = lambda r: arch.registers[r][0]  # noqa: E731
    size = lambda r: arch.registers[r][1]  # noqa: E731
    loader = cle.Loader(request["binary"], auto_load_libs=False, main_opts={"base_addr": 0})
    obj = loader.main_object
    base = int(request.get("base", 0))
    imports = sorted({r.symbol.name for r in obj.relocs if r.symbol is not None and r.symbol.is_import}
                     | set(obj.plt))
    index = {n: i for i, n in enumerate(imports)}
    segs = [(s.vaddr + base, s.memsize, s.offset, s.filesize, s.is_executable) for s in obj.segments]
    relative, slots = [], []
    for r in obj.relocs:
        kind = type(r).__name__
        if kind.endswith("RELATIVE"):
            relative.append((r.relative_addr + base, r.addend + base))
        elif kind.endswith(("JUMP_SLOT", "GLOB_DAT", "ABS64")) and r.symbol is not None and r.symbol.is_import:
            slots.append((r.relative_addr + base, index[r.symbol.name], getattr(r, "addend", 0) or 0))
    translated = [int(a) + base for a in request["translated"]]
    plt = {a + base: index[n] for n, a in obj.plt.items()}
    defaults = [(off(n), size(n), v) for n, v, *_ in arch.default_register_values
                if n in arch.registers and n not in ("sp", "xsp")]
    nl = "\n"
    own = [(index[n], v) for n, v in OWN_DATA.items() if n in index]
    c = f"""#define _GNU_SOURCE
#include "atlas_lift.h"
#include <dlfcn.h>
#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
{TRAMPOLINE}
{nl.join(f"void fn_{a:x}(atlas_state *s);" for a in translated)}
static const char *import_names[] = {{{", ".join(f'"{n}"' for n in imports)}}};
static void *import_host[{len(imports)}];
static uint64_t own_data[{max(len(own), 1)}] = {{{", ".join(f"{v:#x}ULL" for _, v in own) or "0"}}};
enum {{ X0 = {off('x0')}, X1 = {off('x1')}, X2 = {off('x2')}, SP = {off('sp')}, Q0 = {off('q0')}, Q1 = {off('q1')},
        NIMPORTS = {len(imports)} }};

static void call_host(atlas_state *s, void *fn) {{
  struct atlas_native_frame f;
  for (int i = 0; i < 6; i++) f.gp[i] = REG(uint64_t, X0 + 8 * i);
  for (int i = 0; i < 8; i++) memcpy(f.xmm[i], s->r + Q0 + 16 * i, 16);
  /* The host's stack arguments: the guest's x6 and x7, then the guest's own stack arguments. */
  f.stack[0] = REG(uint64_t, X0 + 48); f.stack[1] = REG(uint64_t, X0 + 56);
  for (int i = 2; i < 16; i++) f.stack[i] = LOAD64(REG(uint64_t, SP) + 8 * (i - 2));
  atlas_native(fn, &f);
  REG(uint64_t, X0) = f.rax; REG(uint64_t, X1) = f.rdx;
  memcpy(s->r + Q0, f.xmm0, 16); memcpy(s->r + Q1, f.xmm1, 16);
}}

{jumps_c(off, A64_ARGS, A64_SAVED, size, **A64_FRAME)}
{ENTER_GUEST}
/* A guest function handed to the library (qsort's comparison): stub k enters the guest at callback_target[k]. */
static uint64_t callback_target[{CALLBACK_SLOTS}];
static int callback_count;
{nl.join(f'__attribute__((naked)) static void callback_stub_{k}(void) {{ __asm__ volatile("movabs ${k:#x}, %r11\\n jmp atlas_enter_guest_asm"); }}' for k in range(CALLBACK_SLOTS))}
static void *const callback_stub[{CALLBACK_SLOTS}] = {{{", ".join(f"(void *)callback_stub_{k}" for k in range(CALLBACK_SLOTS))}}};
static const int returns_handler[{len(imports) or 1}] = {{{", ".join("1" if n in RETURNS_HANDLER else "0" for n in imports) or "0"}}};
static const int callback_arg[{len(imports) or 1}] = {{{", ".join(str(CALLBACK_ARGS.get(n, -1)) for n in imports) or "-1"}}};
/* The stub bound to a guest function in the image, or the value unchanged (SIG_DFL, SIG_IGN, a host function). */
static uint64_t bind_callback(uint64_t fn) {{
  if (fn < {min(v for v, *_ in segs):#x}ULL || fn >= {max(v + m for v, m, *_ in segs):#x}ULL) return fn;
  int k = 0;
  while (k < callback_count && callback_target[k] != fn) k++;
  if (k == callback_count) {{
    if (k == {CALLBACK_SLOTS}) {{ fprintf(stderr, "atlas: more than {CALLBACK_SLOTS} guest callbacks\\n"); abort(); }}
    callback_target[callback_count++] = fn;
  }}
  return (uint64_t)(uintptr_t)callback_stub[k];
}}
/* The guest function a stub stands for, or the value unchanged. */
static uint64_t unbind_callback(uint64_t value) {{
  for (int k = 0; k < callback_count; k++)
    if ((uint64_t)(uintptr_t)callback_stub[k] == value) return callback_target[k];
  return value;
}}
static atlas_state *main_state;
/* The library calling stub k: its System V arguments become x0-x5 and d0-d7, the guest state is saved and
 * restored around the call, and x0 or d0 is its result. */
void atlas_enter_guest(uint64_t *frame, uint64_t k) {{
  atlas_state *s = main_state;
  static uint8_t saved[64][sizeof s->r];
  static int depth;
  if (depth == 64) {{ fprintf(stderr, "atlas: callbacks nested too deep\\n"); abort(); }}
  memcpy(saved[depth++], s->r, sizeof s->r);
  for (int i = 0; i < 6; i++) REG(uint64_t, X0 + 8 * i) = frame[i];
  for (int i = 0; i < 8; i++) memcpy(s->r + Q0 + 16 * i, (uint8_t *)frame + 48 + 16 * i, 16);
  REG(uint64_t, SP) = (REG(uint64_t, SP) - 256) & ~15ULL;
  atlas_call(s, callback_target[k]);
  frame[0] = REG(uint64_t, X0);
  memcpy((uint8_t *)frame + 48, s->r + Q0, 16);
  memcpy(s->r, saved[--depth], sizeof s->r);
}}
static int import_of(uint64_t target) {{
  switch (target) {{
{nl.join(f"    case {a:#x}ULL: return {i};" for a, i in sorted(plt.items()))}
  }}
  for (int i = 0; i < NIMPORTS; i++) if (import_host[i] && (uint64_t)(uintptr_t)import_host[i] == target) return i;
  return -1;
}}
static int import_is(uint64_t t, const char *name) {{
  int i = import_of(t);
  return i >= 0 && strcmp(import_names[i], name) == 0;
}}
int atlas_is_setjmp(uint64_t t) {{ return {" || ".join(f'import_is(t, "{n}")' for n in SETJMP_NAMES)}; }}

static char **host_envp;
void atlas_call(atlas_state *s, uint64_t target) {{
  switch (target) {{
{nl.join(f"    case {a:#x}ULL: fn_{a:x}(s); return;" for a in translated)}
  }}
  int i = import_of(target);
  if (i < 0) {{ fprintf(stderr, "atlas: no translation for guest code at %#lx\\n", (unsigned long)target); abort(); }}
  const char *name = import_names[i];
  if ({" || ".join(f'!strcmp(name, "{n}")' for n in LONGJMP_NAMES)}) longjmp_guest(s);
  if (!strcmp(name, "__libc_start_main")) {{
    /* main(argc, argv, envp), then exit with what it returns (identity memory: the host's own pointers). */
    uint64_t guest_main = REG(uint64_t, X0);
    REG(uint64_t, X0) = REG(uint64_t, X1); REG(uint64_t, X1) = REG(uint64_t, X2);
    REG(uint64_t, X2) = (uint64_t)(uintptr_t)host_envp;
    atlas_call(s, guest_main);
    exit((int)REG(uint64_t, X0));
  }}
  if (!strcmp(name, "sigaction")) {{
    /* struct sigaction is laid out the same by glibc on AArch64 and x86-64 (the handler first, 152 bytes): the
     * host's sigaction gets a copy whose handler is the stub bound to the guest's, and an old action handed back
     * names the guest's handler again. A handler that reads its ucontext (SA_SIGINFO) sees the host's. */
    uint8_t act[152];
    uint64_t given = REG(uint64_t, X1), old = REG(uint64_t, X2);
    if (given) {{
      memcpy(act, (void *)(uintptr_t)given, sizeof act);
      uint64_t handler;
      memcpy(&handler, act, 8);
      handler = bind_callback(handler);
      memcpy(act, &handler, 8);
      REG(uint64_t, X1) = (uint64_t)(uintptr_t)act;
    }}
    call_host(s, import_host[i]);
    if (old) {{
      uint64_t handler;
      memcpy(&handler, (void *)(uintptr_t)old, 8);
      handler = unbind_callback(handler);
      memcpy((void *)(uintptr_t)old, &handler, 8);
    }}
    return;
  }}
  if (!import_host[i]) {{ fprintf(stderr, "atlas: import %s not found on this host\\n", name); abort(); }}
  if (callback_arg[i] >= 0) {{
    /* A guest function handed over (an address in the image; the host's own functions are left alone): the
     * library gets the stub bound to it. */
    REG(uint64_t, X0 + 8 * callback_arg[i]) = bind_callback(REG(uint64_t, X0 + 8 * callback_arg[i]));
  }}
  call_host(s, import_host[i]);
  if (returns_handler[i]) REG(uint64_t, X0) = unbind_callback(REG(uint64_t, X0));
}}
void atlas_trap(atlas_state *s, uint64_t at, int kind) {{
  fprintf(stderr, "atlas: guest trap %d at %#lx\\n", kind, (unsigned long)at); abort();
}}
void atlas_syscall(atlas_state *s) {{
  fprintf(stderr, "atlas: the program made a system call of its own\\n"); abort();
}}

int main(int argc, char **argv, char **envp) {{
  host_envp = envp;
  static const struct {{ uint64_t vaddr, memsize, offset, filesize; int exec; }} segs[] = {{
{nl.join(f"    {{{v:#x}ULL, {m:#x}ULL, {o:#x}ULL, {fsz:#x}ULL, {int(x)}}}," for v, m, o, fsz, x in segs)}
  }};
  static const uint64_t relative[][2] = {{ {", ".join(f"{{{a:#x}ULL, {d:#x}ULL}}" for a, d in relative) or "{0, 0}"} }};
  static const uint64_t slots[][3] = {{ {", ".join(f"{{{a:#x}ULL, {i}, {d}}}" for a, i, d in slots) or "{0, 0, 0}"} }};
  FILE *self = fopen({c_string(request["binary"])}, "rb");
  if (!self) {{ perror("atlas: the original binary"); return 127; }}
  for (unsigned k = 0; k < sizeof segs / sizeof segs[0]; k++) {{
    uint64_t lo = segs[k].vaddr & ~0xfffULL, hi = (segs[k].vaddr + segs[k].memsize + 0xfff) & ~0xfffULL;
    void *at = mmap((void *)(uintptr_t)lo, hi - lo, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                    -1, 0);
    if (at == MAP_FAILED && errno != EEXIST) {{ perror("atlas: mapping the original's segments"); return 127; }}
    if (segs[k].filesize) {{
      fseek(self, (long)segs[k].offset, SEEK_SET);
      if (fread((void *)(uintptr_t)segs[k].vaddr, 1, segs[k].filesize, self) != segs[k].filesize) return 127;
    }}
  }}
  fclose(self);
  for (int i = 0; i < NIMPORTS; i++) import_host[i] = dlsym(RTLD_DEFAULT, import_names[i]);
{nl.join(f"  import_host[{i}] = &own_data[{k}];" for k, (i, _) in enumerate(own))}
  for (unsigned k = 0; k < sizeof relative / sizeof relative[0]; k++)
    if (relative[k][0]) *(uint64_t *)(uintptr_t)relative[k][0] = relative[k][1];
  for (unsigned k = 0; k < sizeof slots / sizeof slots[0]; k++)
    if (slots[k][0]) *(uint64_t *)(uintptr_t)slots[k][0] = (uint64_t)(uintptr_t)import_host[slots[k][1]] + slots[k][2];
  static atlas_state st;
  atlas_state *s = &st;
  main_state = s;
  /* The guest's stack: 8 MiB of host memory; argc, argv and envp in place as the kernel lays them. */
  uint8_t *stack = mmap(NULL, 8 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  uint64_t sp = ((uint64_t)(uintptr_t)(stack + (8 << 20) - 4096)) & ~15ULL;
  int envc = 0; while (envp[envc]) envc++;
  sp -= 8 * (uint64_t)(argc + envc + 3); sp &= ~15ULL;
  uint64_t *p = (uint64_t *)(uintptr_t)sp;
  p[0] = (uint64_t)argc;
  for (int i = 0; i < argc; i++) p[1 + i] = (uint64_t)(uintptr_t)argv[i];
  p[1 + argc] = 0;
  for (int i = 0; i < envc; i++) p[2 + argc + i] = (uint64_t)(uintptr_t)envp[i];
  p[2 + argc + envc] = 0;
{nl.join(f"  memcpy(s->r + {o}, &(uint64_t){{{v:#x}ULL}}, {n});" for o, n, v in defaults)}
  REG(uint64_t, SP) = sp;
  REG(uint64_t, X0) = 0; /* rtld_fini: no dynamic loader to call back at exit */
  atlas_call(s, {obj.entry + base:#x}ULL);
  return 0;
}}
"""
    out = request["out"]
    with open(out + ".main.c", "w") as f:
        f.write(c)
    with open(out + ".setjmp.h", "w") as f:
        f.write(SETJMP_HEADER)
    subprocess.run(["gcc", "-O1", "-w", "-I", request["runtime"], "-include", out + ".setjmp.h", *request["lifted"],
                    out + ".main.c", "-o", out, "-ldl", "-lm"], check=True)
    print(json.dumps({"executable": out, "imports": len(imports), "own": sorted(n for n in OWN_DATA if n in index)}))


if __name__ == "__main__":
    main()
