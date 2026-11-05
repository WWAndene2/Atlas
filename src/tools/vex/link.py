"""Links a program's translations (lift.py) into an executable that runs on a host of the same architecture.

argv[1]: request JSON {"binary": path, "arch": name, "lifted": [paths of translated C], "runtime": dir of
                       atlas_lift.h, "translated": [int], "out": path of the executable}
stdout: {"executable": path, "imports": int, "unresolved": [names]}

Identity memory: the original's loaded segments are mapped at their own addresses (a position-independent image
at the addresses the graph uses, from 0, the first 64 KiB left out as the kernel reserves them), so guest
pointers are host pointers: the C library is called as it is, through a trampoline passing the argument registers
(integer and vector), sixteen stack words for further arguments, and getting rax, rdx, xmm0 and xmm1 back. Relocations
are applied as the dynamic loader would: relative ones, import slots (the host function's address), copies
(stdout...). Calls to an import's PLT stub or to a host function's address go to the trampoline; setjmp runs in the
translated caller's frame (ATLAS_CALL), and longjmp returns there with the guest's saved registers. The program
starts at the original's entry, whose call to __libc_start_main runs the translated main. x86-64 Linux ELF.
"""

import json
import subprocess
import sys

import archinfo
import cle

TRAMPOLINE = r"""
/* Calls a host function with the guest's argument registers: frame layout in atlas_native_frame. */
struct atlas_native_frame { uint64_t gp[6]; uint8_t xmm[8][16]; uint64_t stack[16]; uint64_t rax, rdx;
                            uint8_t xmm0[16], xmm1[16]; };
__attribute__((naked)) static void atlas_native(void *fn, struct atlas_native_frame *f) {
  __asm__ volatile(
    "push %rbp\n mov %rsp,%rbp\n push %rbx\n push %r12\n"
    "mov %rdi,%r12\n mov %rsi,%rbx\n"
    "sub $136,%rsp\n and $-16,%rsp\n"
    "xor %ecx,%ecx\n1: mov 176(%rbx,%rcx,8),%rax\n mov %rax,(%rsp,%rcx,8)\n inc %ecx\n cmp $16,%ecx\n jne 1b\n"
    "movdqu 48(%rbx),%xmm0\n movdqu 64(%rbx),%xmm1\n movdqu 80(%rbx),%xmm2\n movdqu 96(%rbx),%xmm3\n"
    "movdqu 112(%rbx),%xmm4\n movdqu 128(%rbx),%xmm5\n movdqu 144(%rbx),%xmm6\n movdqu 160(%rbx),%xmm7\n"
    "mov 0(%rbx),%rdi\n mov 8(%rbx),%rsi\n mov 16(%rbx),%rdx\n mov 24(%rbx),%rcx\n mov 32(%rbx),%r8\n"
    "mov 40(%rbx),%r9\n mov $8,%eax\n call *%r12\n"
    "mov %rax,304(%rbx)\n mov %rdx,312(%rbx)\n movdqu %xmm0,320(%rbx)\n movdqu %xmm1,336(%rbx)\n"
    "lea -16(%rbp),%rsp\n pop %r12\n pop %rbx\n pop %rbp\n ret\n");
}
"""


# Included before every translation: a call to setjmp runs the host's setjmp in the translated caller's own frame,
# so a later longjmp lands back in it, alive, as in C.
SETJMP_HEADER = """#include <setjmp.h>
#include <stdint.h>
struct atlas_state;
int atlas_is_setjmp(uint64_t target);
void *atlas_jump_buf(struct atlas_state *s);
void atlas_jump_first(struct atlas_state *s);
void atlas_jump_back(struct atlas_state *s);
#define ATLAS_CALL(t) do { uint64_t t_ = (t); if (atlas_is_setjmp(t_)) { \\
    if (setjmp(*(jmp_buf *)atlas_jump_buf(s))) atlas_jump_back(s); else atlas_jump_first(s); \\
  } else atlas_call(s, t_); } while (0)
"""


def main():
    request = json.load(open(sys.argv[1]))
    arch = archinfo.arch_from_id(request["arch"])
    off = lambda r: arch.registers[r][0]  # noqa: E731
    loader = cle.Loader(request["binary"], auto_load_libs=False, main_opts={"base_addr": 0})
    obj = loader.main_object
    # Imports: functions and data the host's libraries provide; a copy relocation's symbol counts (stdout...).
    imports = sorted({r.symbol.name for r in obj.relocs if r.symbol is not None
                      and (r.symbol.is_import or type(r).__name__.endswith("COPY"))} | set(obj.plt))
    index = {n: i for i, n in enumerate(imports)}
    segs = [(s.vaddr, s.memsize, obj.binary_stream_offset if False else s.offset, s.filesize, s.is_executable)
            for s in obj.segments]
    relative, slots, copies = [], [], []
    for r in obj.relocs:
        kind = type(r).__name__
        if kind.endswith("RELATIVE"):
            relative.append((r.relative_addr, r.addend))
        elif kind.endswith(("JUMP_SLOT", "GLOB_DAT", "_64")) and r.symbol is not None and r.symbol.is_import:
            slots.append((r.relative_addr, index[r.symbol.name], getattr(r, "addend", 0) if kind.endswith("_64") else 0))
        elif kind.endswith("COPY") and r.symbol is not None:
            copies.append((r.relative_addr, index[r.symbol.name], r.symbol.size))
    translated = [int(a) for a in request["translated"]]
    plt = {a: index[n] for n, a in obj.plt.items()}
    names = ",".join(f'"{n}"' for n in imports)
    c = f"""#define _GNU_SOURCE
#define ATLAS_IDENTITY
#include "atlas_lift.h"
#include <dlfcn.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
{TRAMPOLINE}
{chr(10).join(f"void fn_{a:x}(atlas_state *s);" for a in translated)}
static const char *import_names[] = {{{names}}};
static void *import_host[{len(imports)}];
enum {{ RDI = {off('rdi')}, RSI = {off('rsi')}, RDX = {off('rdx')}, RCX = {off('rcx')}, R8 = {off('r8')},
        R9 = {off('r9')}, RAX = {off('rax')}, RSP = {off('rsp')}, RBP = {off('rbp')}, RBX = {off('rbx')},
        R12 = {off('r12')}, R13 = {off('r13')}, R14 = {off('r14')}, R15 = {off('r15')}, XMM0 = {off('xmm0')},
        FS = {off('fs_const') if 'fs_const' in arch.registers else off('fs')}, NIMPORTS = {len(imports)} }};

static void call_host(atlas_state *s, void *fn) {{
  struct atlas_native_frame f;
  static const int gp[6] = {{RDI, RSI, RDX, RCX, R8, R9}};
  for (int i = 0; i < 6; i++) f.gp[i] = REG(uint64_t, gp[i]);
  for (int i = 0; i < 8; i++) memcpy(f.xmm[i], s->r + XMM0 + 32 * i, 16);
  /* Stack arguments start above the return address the guest's call pushed. */
  for (int i = 0; i < 16; i++) f.stack[i] = LOAD64(REG(uint64_t, RSP) + 8 + 8 * i);
  atlas_native(fn, &f);
  REG(uint64_t, RAX) = f.rax; REG(uint64_t, RDX) = f.rdx;
  memcpy(s->r + XMM0, f.xmm0, 16); memcpy(s->r + XMM0 + 32, f.xmm1, 16);
  REG(uint64_t, RSP) += 8; /* the import returns: pop the guest's return address */
}}

/* setjmp/longjmp: a host jmp_buf per guest jmp_buf, with the guest registers to restore. */
struct jump {{ uint64_t guest; jmp_buf host; uint64_t regs[8]; uint64_t value; }};
static struct jump jumps[256];
static struct jump *jump_for(uint64_t guest) {{
  for (int i = 0; i < 256; i++) if (jumps[i].guest == guest || jumps[i].guest == 0) {{ jumps[i].guest = guest; return &jumps[i]; }}
  abort();
}}
static const int saved[8] = {{RSP, RBP, RBX, R12, R13, R14, R15, RAX}};
static int import_is(uint64_t t, const char *name);
static struct jump *landing;
static void longjmp_guest(atlas_state *s) {{
  struct jump *j = jump_for(REG(uint64_t, RDI));
  j->value = REG(uint64_t, RSI) ? REG(uint64_t, RSI) : 1;
  landing = j;
  longjmp(j->host, 1);
}}
void *atlas_jump_buf(atlas_state *s) {{
  struct jump *j = jump_for(REG(uint64_t, RDI));
  for (int k = 0; k < 8; k++) j->regs[k] = REG(uint64_t, saved[k]);
  return &j->host;
}}
/* setjmp's first return: 0, and the return address the guest's call pushed popped. */
void atlas_jump_first(atlas_state *s) {{ REG(uint64_t, RAX) = 0; REG(uint64_t, RSP) += 8; }}
/* Back from a longjmp: the registers as setjmp saw them, the value longjmp passed. */
void atlas_jump_back(atlas_state *s) {{
  for (int k = 0; k < 8; k++) REG(uint64_t, saved[k]) = landing->regs[k];
  REG(uint64_t, RAX) = landing->value;
  REG(uint64_t, RSP) += 8;
}}

static int import_of(uint64_t target) {{
  switch (target) {{
{chr(10).join(f"    case {a:#x}ULL: return {i};" for a, i in sorted(plt.items()))}
  }}
  for (int i = 0; i < NIMPORTS; i++) if (import_host[i] && (uint64_t)(uintptr_t)import_host[i] == target) return i;
  return -1;
}}
static int import_is(uint64_t t, const char *name) {{
  int i = import_of(t);
  return i >= 0 && strcmp(import_names[i], name) == 0;
}}
int atlas_is_setjmp(uint64_t t) {{ return import_is(t, "_setjmp") || import_is(t, "setjmp") || import_is(t, "__sigsetjmp"); }}

static atlas_state *main_state;
static int guest_main_called;
/* ATLAS_TRACE_CALLS=<file>: every call to a translated function, in order, one address per line (to set beside
 * the original's, traced with atlas trace, and find where the two runs part). */
static FILE *trace_calls;
void atlas_call(atlas_state *s, uint64_t target) {{
  if (trace_calls) fprintf(trace_calls, "%#lx\\n", (unsigned long)target);
  switch (target) {{
{chr(10).join(f"    case {a:#x}ULL: fn_{a:x}(s); return;" for a in translated)}
  }}
  int i = import_of(target);
  if (i < 0) {{ fprintf(stderr, "atlas: no translation for guest code at %#lx\\n", (unsigned long)target); abort(); }}
  const char *name = import_names[i];
  if (!strcmp(name, "__longjmp_chk") || !strcmp(name, "longjmp") || !strcmp(name, "_longjmp") || !strcmp(name, "siglongjmp"))
    longjmp_guest(s);
  if (!strcmp(name, "__libc_start_main")) {{
    /* Run the guest's main with the host's arguments (identity memory: the same pointers), then exit. */
    uint64_t guest_main = REG(uint64_t, RDI);
    REG(uint64_t, RDI) = REG(uint64_t, RSI); REG(uint64_t, RSI) = REG(uint64_t, RDX);
    REG(uint64_t, RDX) = REG(uint64_t, RDX) + 8 * (REG(uint64_t, RDI) + 1);
    /* Instead of _start's call: its return address off, main's pushed, so main sees the stack as the ABI says. */
    STORE64(REG(uint64_t, RSP), 0);
    atlas_call(s, guest_main);
    exit((int)REG(uint64_t, RAX));
  }}
  if (!import_host[i]) {{ fprintf(stderr, "atlas: import %s not found on this host\\n", name); abort(); }}
  call_host(s, import_host[i]);
}}
void atlas_trap(atlas_state *s, uint64_t at, int kind) {{
  fprintf(stderr, "atlas: guest trap %d at %#lx\\n", kind, (unsigned long)at); abort();
}}

int main(int argc, char **argv, char **envp) {{
  static const struct {{ uint64_t vaddr, memsize, offset, filesize; int exec; }} segs[] = {{
{chr(10).join(f"    {{{v:#x}ULL, {m:#x}ULL, {o:#x}ULL, {fsz:#x}ULL, {int(x)}}}," for v, m, o, fsz, x in segs)}
  }};
  static const uint64_t relative[][2] = {{ {", ".join(f"{{{a:#x}ULL, {d:#x}ULL}}" for a, d in relative) or "{0, 0}"} }};
  static const uint64_t slots[][3] = {{ {", ".join(f"{{{a:#x}ULL, {i}, {d}}}" for a, i, d in slots) or "{0, 0, 0}"} }};
  static const uint64_t copies[][3] = {{ {", ".join(f"{{{a:#x}ULL, {i}, {n}}}" for a, i, n in copies) or "{0, 0, 0}"} }};
  FILE *self = fopen("{request["binary"]}", "rb");
  if (!self) {{ perror("atlas: the original binary"); return 127; }}
  for (unsigned k = 0; k < sizeof segs / sizeof segs[0]; k++) {{
    uint64_t lo = segs[k].vaddr & ~0xfffULL, hi = (segs[k].vaddr + segs[k].memsize + 0xfff) & ~0xfffULL;
    if (lo < 0x10000) lo = 0x10000; /* the kernel keeps the first 64 KiB: an image's header lives there */
    if (hi <= lo) continue;
    void *at = mmap((void *)(uintptr_t)lo, hi - lo, PROT_READ | PROT_WRITE | (segs[k].exec ? PROT_EXEC : 0),
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (at == MAP_FAILED) {{ perror("atlas: mapping the original's segments"); return 127; }}
    uint64_t from = segs[k].vaddr < lo ? lo : segs[k].vaddr, skip = from - segs[k].vaddr;
    if (segs[k].filesize > skip) {{
      fseek(self, (long)(segs[k].offset + skip), SEEK_SET);
      if (fread((void *)(uintptr_t)from, 1, segs[k].filesize - skip, self) != segs[k].filesize - skip) return 127;
    }}
  }}
  fclose(self);
  for (int i = 0; i < NIMPORTS; i++) import_host[i] = dlsym(RTLD_DEFAULT, import_names[i]);
  if (getenv("ATLAS_TRACE_CALLS")) trace_calls = fopen(getenv("ATLAS_TRACE_CALLS"), "w");
  for (unsigned k = 0; k < sizeof relative / sizeof relative[0]; k++)
    if (relative[k][0]) *(uint64_t *)(uintptr_t)relative[k][0] = relative[k][1];
  for (unsigned k = 0; k < sizeof slots / sizeof slots[0]; k++)
    if (slots[k][0]) *(uint64_t *)(uintptr_t)slots[k][0] = (uint64_t)(uintptr_t)import_host[slots[k][1]] + slots[k][2];
  for (unsigned k = 0; k < sizeof copies / sizeof copies[0]; k++)
    if (copies[k][0] && import_host[copies[k][1]]) memcpy((void *)(uintptr_t)copies[k][0], import_host[copies[k][1]], copies[k][2]);
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
  REG(uint64_t, RSP) = sp;
  uint64_t fs; __asm__ volatile("mov %%fs:0, %0" : "=r"(fs)); REG(uint64_t, FS) = fs;
  atlas_call(s, {obj.entry:#x}ULL);
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
    unresolved = []
    print(json.dumps({"executable": out, "imports": len(imports), "unresolved": unresolved}))


if __name__ == "__main__":
    main()
