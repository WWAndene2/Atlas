"""Links a Windows x64 program's translations (lift.py) into an executable for an x86-64 Linux host.

Request, a JSON file named on the command line: {"binary": path of the PE (built into the program),
"lifted": [paths of the translations' C], "translated": [addresses], "runtime": directory of atlas_lift.h and the
win_*.inc services, "out": path of the executable}
stdout: {"executable": path, "imports": int, "stubs": int, "unserved": [names]}

Identity memory, as link.py: the image is mapped at its ImageBase (headers and sections), so guest pointers are
host pointers. Each import slot holds a placeholder address the dispatch recognises (a data import's slot holds the
address of its host variable instead). A call to an import runs its service (win_*.inc) through a trampoline that
passes the guest's Windows x64 arguments as they are: rcx, rdx, r8, r9, xmm0-xmm3, and the stack from the shadow
space on; rax and xmm0 come back. The services that call guest code (_initterm, _onexit, atexit, exit) and
setjmp/longjmp are served here. The thread's TEB (gs) is a block of host memory whose self pointer and stack bounds
are set. TLS callbacks run, as the Windows loader runs them, before the entry point (the C runtime's
mainCRTStartup, which calls the translated main).
"""

import json
import os
import re
import subprocess
import sys

import archinfo
import pefile

from embed import embed_original
from jumps import LONGJMP_NAMES, SETJMP_HEADER, SETJMP_NAMES, WIN64_ARGS, WIN64_SAVED, jumps_c

SERVICES = ["win_base.inc", "win_stdio.inc", "win_string.inc", "win_time.inc", "win_process.inc",
            "win_kernel32.inc", "win_printf.inc"]
# Imports that are data: their slot holds the address of the host variable (win_process.inc).
DATA = {"_commode": "win_commode", "_fmode": "win_fmode", "__initenv": "win_initenv"}
# Imports served here, in the dispatch, because they call guest code or end the program.
HERE = {"__getmainargs", "_initterm", "_onexit", "atexit", "exit", "_exit", "_cexit", "_amsg_exit",
        "__C_specific_handler", *SETJMP_NAMES, *LONGJMP_NAMES}
PLACEHOLDER = 0x7FFF00000000  # import i is called at PLACEHOLDER + 16 i: no guest code lies there

# Calls an ms_abi service with the guest's registers and stack: frame = {gp[4] (rcx, rdx, r8, r9), xmm[4][16],
# stack[16] (from the shadow space on), rax, xmm0[16]}.
TRAMPOLINE = r"""
struct atlas_win_frame { uint64_t gp[4]; uint8_t xmm[4][16]; uint64_t stack[16]; uint64_t rax; uint8_t xmm0[16]; };
__attribute__((naked)) static void atlas_win_native(void *fn, struct atlas_win_frame *f) {
  __asm__ volatile(
    "push %rbp\n mov %rsp,%rbp\n push %rbx\n push %r12\n"
    "mov %rdi,%r12\n mov %rsi,%rbx\n"
    "sub $136,%rsp\n and $-16,%rsp\n"
    "xor %ecx,%ecx\n1: mov 96(%rbx,%rcx,8),%rax\n mov %rax,(%rsp,%rcx,8)\n inc %ecx\n cmp $16,%ecx\n jne 1b\n"
    "movdqu 32(%rbx),%xmm0\n movdqu 48(%rbx),%xmm1\n movdqu 64(%rbx),%xmm2\n movdqu 80(%rbx),%xmm3\n"
    "mov 0(%rbx),%rcx\n mov 8(%rbx),%rdx\n mov 16(%rbx),%r8\n mov 24(%rbx),%r9\n"
    "call *%r12\n"
    "mov %rax,224(%rbx)\n movdqu %xmm0,232(%rbx)\n"
    "lea -16(%rbp),%rsp\n pop %r12\n pop %rbx\n pop %rbp\n ret\n");
}
"""


def c_string(text):
    """A C string literal for any path, every byte escaped in octal."""
    return '"' + "".join(f"\\{b:03o}" for b in text.encode()) + '"'


def served(runtime):
    """The services the win_*.inc files define, by import name (a function w_<name>)."""
    names = set()
    for f in SERVICES:
        names.update(re.findall(r"^WIN static [^(]*?\bw_(\w+)\(", open(os.path.join(runtime, f)).read(), re.M))
    return names


def import_stubs(pe, slot_index):
    """The import stubs in the code (jmp [rip+slot] onto an import slot, how MinGW calls an import), by address:
    a call to one is a call to its import. The graph keeps them as thunks, which are not translated."""
    stubs = {}
    base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            continue
        data = section.get_data()
        at = base + section.VirtualAddress
        for k in range(len(data) - 5):
            if data[k] == 0xFF and data[k + 1] == 0x25:
                target = at + k + 6 + int.from_bytes(data[k + 2:k + 6], "little", signed=True)
                if target in slot_index:
                    stubs[at + k] = slot_index[target]
    return stubs


def main():
    request = json.load(open(sys.argv[1]))
    arch = archinfo.arch_from_id("AMD64")
    off = lambda r: arch.registers[r][0]  # noqa: E731
    size = lambda r: arch.registers[r][1]  # noqa: E731
    pe = pefile.PE(request["binary"])
    image_base = pe.OPTIONAL_HEADER.ImageBase
    image_size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF
    sections = [(image_base + s.VirtualAddress, s.PointerToRawData, min(s.SizeOfRawData, max(s.Misc_VirtualSize, 0)
                 or s.SizeOfRawData)) for s in pe.sections]
    imports = []  # (slot address, name)
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            imports.append((imp.address, imp.name.decode() if imp.name else f"ordinal_{imp.ordinal}"))
    names = [n for _, n in imports]
    stubs = import_stubs(pe, {a: i for i, (a, _) in enumerate(imports)})
    have = served(request["runtime"])
    unserved = sorted({n for n in names if n not in have and n not in HERE and n not in DATA})
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    tls_callbacks = tls.struct.AddressOfCallBacks if tls is not None else 0
    translated = [int(a) for a in request["translated"]]
    defaults = [(off(n), size(n), v) for n, v, *_ in arch.default_register_values
                if n in arch.registers and n not in ("rsp", "fs", "gs")]
    nl = "\n"

    def service(i, n):
        if n in DATA:
            return "0"
        return f"(void *)w_{n}" if n in have else "0"

    c = f"""#define _GNU_SOURCE
#include "atlas_lift.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
{nl.join(f'#include "{f}"' for f in SERVICES)}
{TRAMPOLINE}
{nl.join(f"void fn_{a:x}(atlas_state *s);" for a in translated)}
enum {{ RCX = {off('rcx')}, RDX = {off('rdx')}, R8 = {off('r8')}, R9 = {off('r9')}, RAX = {off('rax')},
        RSP = {off('rsp')}, GS = {off('gs_const')}, NIMPORTS = {len(imports)} }};
static const char *import_names[] = {{{", ".join(f'"{n}"' for n in names) or '""'}}};
static void *import_service[] = {{{", ".join(service(i, n) for i, n in enumerate(names)) or "0"}}};

{jumps_c(off, WIN64_ARGS, WIN64_SAVED, size)}
static int import_index(uint64_t t) {{
  switch (t) {{
{nl.join(f"    case {a:#x}ULL: return {i};" for a, i in sorted(stubs.items()))}
  }}
  if (t < {PLACEHOLDER:#x}ULL || t >= {PLACEHOLDER:#x}ULL + 16ULL * NIMPORTS || (t & 15)) return -1;
  return (int)((t - {PLACEHOLDER:#x}ULL) / 16);
}}
static int import_is(uint64_t t, const char *name) {{
  int i = import_index(t);
  return i >= 0 && strcmp(import_names[i], name) == 0;
}}
int atlas_is_setjmp(uint64_t t) {{ return {" || ".join(f'import_is(t, "{n}")' for n in SETJMP_NAMES)}; }}

/* A call of guest code from a service: Windows x64 arguments, 16-byte alignment and shadow space as after a call. */
static void guest_call(atlas_state *s, uint64_t target, uint64_t a, uint64_t b, uint64_t c) {{
  uint64_t before = REG(uint64_t, RSP);
  uint64_t sp = ((before - 64) & ~15ULL) - 8;
  STORE64(sp, 0);
  REG(uint64_t, RSP) = sp;
  REG(uint64_t, RCX) = a; REG(uint64_t, RDX) = b; REG(uint64_t, R8) = c;
  /* Guest code run for the host leaves s->returned as its own last return set it: the call site waiting on the
   * host (an import's, a callback's) must still see what it expects. */
  uint64_t returned = s->returned;
  atlas_call(s, target);
  s->returned = returned;
  REG(uint64_t, RSP) = before;
}}

/* ATLAS_COVERAGE=<file>: the translated functions that ran, written at exit, as link.py does. */
static uint8_t covered[{len(translated) or 1}];
static const uint64_t covered_address[{len(translated) or 1}] = {{{", ".join(f"{a:#x}ULL" for a in translated) or "0"}}};
static const char *coverage_file;
static void write_coverage(void) {{
  FILE *f = fopen(coverage_file, "w");
  if (!f) return;
  for (unsigned k = 0; k < sizeof covered; k++) if (covered[k]) fprintf(f, "%#lx\\n", (unsigned long)covered_address[k]);
  fclose(f);
}}
static int host_argc;
static char **host_argv, **host_envp;
static uint64_t at_exit[64];
static int at_exit_count;
static void run_at_exit(atlas_state *s) {{
  while (at_exit_count > 0) guest_call(s, at_exit[--at_exit_count], 0, 0, 0);
}}

static void serve_here(atlas_state *s, const char *name) {{
  uint64_t a = REG(uint64_t, RCX), b = REG(uint64_t, RDX), c = REG(uint64_t, R8);
  if (!strcmp(name, "__getmainargs")) {{
    *(int *)(uintptr_t)a = host_argc; *(char ***)(uintptr_t)b = host_argv; *(char ***)(uintptr_t)c = host_envp;
    REG(uint64_t, RAX) = 0;
  }} else if (!strcmp(name, "_initterm")) {{
    for (uint64_t p = a; p < b; p += 8)
      if (LOAD64(p)) guest_call(s, LOAD64(p), 0, 0, 0);
  }} else if (!strcmp(name, "_onexit") || !strcmp(name, "atexit")) {{
    if (at_exit_count == 64) {{ REG(uint64_t, RAX) = !strcmp(name, "atexit") ? (uint64_t)-1 : 0; return; }}
    at_exit[at_exit_count++] = a;
    REG(uint64_t, RAX) = !strcmp(name, "atexit") ? 0 : a;
  }} else if (!strcmp(name, "exit")) {{
    run_at_exit(s); fflush(NULL); exit((int)a);
  }} else if (!strcmp(name, "_exit")) {{
    fflush(NULL); _exit((int)a);
  }} else if (!strcmp(name, "_cexit")) {{
    run_at_exit(s); fflush(NULL);
  }} else if (!strcmp(name, "_amsg_exit")) {{
    fprintf(stderr, "runtime error R60%02d\\n", (int)a); fflush(NULL); exit(255);
  }} else if ({" || ".join(f'!strcmp(name, "{n}")' for n in LONGJMP_NAMES)}) {{
    longjmp_guest(s);
  }} else {{
    fprintf(stderr, "atlas: %s is not served (only the system calls it from outside the program)\\n", name);
    abort();
  }}
}}

static void call_import(atlas_state *s, int i) {{
  const char *name = import_names[i];
  if (!import_service[i]) {{
    serve_here(s, name);
  }} else {{
    struct atlas_win_frame f;
    static const int gp[4] = {{RCX, RDX, R8, R9}};
    static const int xmm[4] = {{{", ".join(str(off(f"xmm{k}")) for k in range(4))}}};
    for (int k = 0; k < 4; k++) {{ f.gp[k] = REG(uint64_t, gp[k]); memcpy(f.xmm[k], s->r + xmm[k], 16); }}
    for (int k = 0; k < 16; k++) f.stack[k] = LOAD64(REG(uint64_t, RSP) + 8 + 8 * k);
    atlas_win_native(import_service[i], &f);
    REG(uint64_t, RAX) = f.rax;
    memcpy(s->r + xmm[0], f.xmm0, 16);
  }}
  /* The import returns: to the address the guest's call pushed (s->returned, for the call site to check: a tail
   * jump to an import returns to its caller's caller), which it pops. */
  s->returned = LOAD64(REG(uint64_t, RSP));
  REG(uint64_t, RSP) += 8;
}}

void atlas_call(atlas_state *s, uint64_t target) {{
  switch (target) {{
{nl.join(f"    case {a:#x}ULL: covered[{k}] = 1; fn_{a:x}(s); return;" for k, a in enumerate(translated))}
  }}
  int i = import_index(target);
  if (i >= 0) {{ call_import(s, i); return; }}
  /* A thunk the graph keeps untranslated (jmp rel32 to a function): followed in the original's code. */
  uint8_t *code = (uint8_t *)(uintptr_t)target;
  if (target >= {image_base:#x}ULL && target < {image_base + image_size - 5:#x}ULL && code[0] == 0xE9) {{
    int32_t rel;
    memcpy(&rel, code + 1, 4);
    atlas_call(s, target + 5 + (int64_t)rel);
    return;
  }}
  fprintf(stderr, "atlas: no translation for guest code at %#lx\\n", (unsigned long)target);
  abort();
}}
void atlas_trap(atlas_state *s, uint64_t at, int kind) {{
  fprintf(stderr, "atlas: guest trap %d at %#lx\\n", kind, (unsigned long)at); abort();
}}
void atlas_syscall(atlas_state *s) {{
  fprintf(stderr, "atlas: a Windows program made a system call\\n"); abort();
}}

{embed_original(request["binary"])}
int main(int argc, char **argv, char **envp) {{
  host_argc = argc; host_argv = argv; host_envp = envp;
  if ((coverage_file = getenv("ATLAS_COVERAGE")) != NULL) atexit(write_coverage);
  win_initenv = envp;
  win_module_path = {c_string(os.path.abspath(request["binary"]))};
  uint8_t *image = mmap((void *)(uintptr_t){image_base:#x}ULL, {image_size:#x}, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (image == MAP_FAILED) {{ perror("atlas: mapping the image at its base"); return 127; }}
  static const uint64_t parts[][3] = {{ {{{image_base:#x}ULL, 0, {pe.OPTIONAL_HEADER.SizeOfHeaders:#x}}},
{nl.join(f"    {{{v:#x}ULL, {o:#x}, {n:#x}}}," for v, o, n in sections if n)}
  }};
  for (unsigned k = 0; k < sizeof parts / sizeof parts[0]; k++)
    memcpy((void *)(uintptr_t)parts[k][0], atlas_original + parts[k][1], parts[k][2]);
  /* Import slots: placeholders the dispatch recognises, or a data import's host address. */
{nl.join(f"  *(uint64_t *)(uintptr_t){a:#x}ULL = (uint64_t)(uintptr_t)&{DATA[n]};" if n in DATA else f"  *(uint64_t *)(uintptr_t){a:#x}ULL = {PLACEHOLDER + 16 * i:#x}ULL;" for i, (a, n) in enumerate(imports))}
  static atlas_state st;
  atlas_state *s = &st;
  /* The guest's stack (8 MiB) and TEB: self pointer at 0x30, stack base and limit at 8 and 0x10. */
  uint8_t *stack = mmap(NULL, 8 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  static uint64_t teb[512];
  teb[1] = (uint64_t)(uintptr_t)(stack + (8 << 20)); teb[2] = (uint64_t)(uintptr_t)stack;
  teb[6] = (uint64_t)(uintptr_t)teb;
  REG(uint64_t, GS) = (uint64_t)(uintptr_t)teb;
{nl.join(f"  memcpy(s->r + {o}, &(uint64_t){{{v:#x}ULL}}, {n});" for o, n, v in defaults)}
  REG(uint64_t, RSP) = (((uint64_t)(uintptr_t)(stack + (8 << 20) - 4096)) & ~15ULL) - 8;
  /* TLS callbacks, as the loader runs them: (module, DLL_PROCESS_ATTACH, 0). */
  for (uint64_t p = {tls_callbacks:#x}ULL; p && LOAD64(p); p += 8) guest_call(s, LOAD64(p), {image_base:#x}ULL, 1, 0);
  atlas_call(s, {image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint:#x}ULL);
  run_at_exit(s);
  fflush(NULL);
  return (int)REG(uint32_t, RAX);
}}
"""
    out = request["out"]
    with open(out + ".main.c", "w") as f:
        f.write(c)
    with open(out + ".setjmp.h", "w") as f:
        f.write(SETJMP_HEADER)
    subprocess.run(["gcc", "-O1", "-w", "-I", request["runtime"], "-include", out + ".setjmp.h", *request["lifted"],
                    out + ".main.c", "-o", out, "-lm"], check=True)
    print(json.dumps({"executable": out, "imports": len(imports), "stubs": len(stubs), "unserved": unserved}))


if __name__ == "__main__":
    main()
