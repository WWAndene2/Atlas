"""Links a binary's translations into a program when the guest's CPU is not the host's (an ARM game run on a PC).

Unlike link.py (guest = host, the C library called natively), the guest here is self-contained: a statically linked
ELF whose own code, C library included, is translated. Guest memory is a block of host memory, and a guest address
a is reached at mem + a (the runtime's flat mapping), so nothing of the host leaks in. What the guest asks of its
operating system is served by atlas_syscall, which reads the system-call number and arguments from the guest
registers and carries out the common Linux calls on the guest's memory. This is the console case in miniature: the
code is faithful, the platform's services are emulated.

Only the register layout and system-call convention are architecture-specific (CONVENTIONS); the rest is shared.
"""

import json
import sys

import archinfo
import cle

# Per architecture: the registers a Linux system call reads (number, then up to seven arguments, then where the
# result goes), as archinfo names them. ARM EABI: r7 holds the number, r0-r6 the arguments, r0 the result.
CONVENTIONS = {
    "ARMEL": {"number": "r7", "args": ["r0", "r1", "r2", "r3", "r4", "r5", "r6"], "result": "r0", "word": 4},
    "ARMHF": {"number": "r7", "args": ["r0", "r1", "r2", "r3", "r4", "r5", "r6"], "result": "r0", "word": 4},
}

GUEST_SIZE = 0x40000000  # 1 GiB of guest memory


def main():
    request = json.load(open(sys.argv[1]))
    arch = archinfo.arch_from_id(request["arch"], request.get("endness", "any"))
    conv = CONVENTIONS[arch.name]
    off = {r: arch.registers[r][0] for r in [conv["number"], conv["result"], *conv["args"], "sp"]}
    loader = cle.Loader(request["binary"], auto_load_libs=False)
    obj = loader.main_object
    translated = [int(a) for a in request["translated"]]
    segs = [(s.vaddr, s.memsize, s.offset, s.filesize) for s in obj.segments]
    image_end = (max(s.vaddr + s.memsize for s in obj.segments) + 0xFFF) & ~0xFFF
    layout = {"ATLAS_GUEST_BRK": image_end, "ATLAS_GUEST_MMAP": 0x20000000, "ATLAS_GUEST_TOP": 0x3F000000}
    tls = arch.registers["tpidruro"][0] if "tpidruro" in arch.registers else None

    big = "#define ATLAS_BIG_ENDIAN\n" if arch.memory_endness == "Iend_BE" else ""
    defaults = [
        (arch.registers[n][0], arch.registers[n][1], v)
        for n, v, *_ in arch.default_register_values
        if n in arch.registers and n not in ("sp", "pc")
    ]
    args = ", ".join(f"REG(uint32_t, {off[r]})" for r in conv["args"])
    tls_case = (
        f"  if (number == 0xf0005) {{ REG(uint32_t, {tls}) = REG(uint32_t, {off[conv['args'][0]]}); "
        f"REG(uint32_t, {off[conv['result']]}) = 0; return; }}\n"
        if tls is not None
        else ""
    )
    c = f"""{big}#include "atlas_lift.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
{chr(10).join(f"#define {k} {v:#x}ULL" for k, v in layout.items())}
{chr(10).join(f"void fn_{a:x}(atlas_state *s);" for a in translated)}
void atlas_call(atlas_state *s, uint64_t target) {{
  switch (target) {{
{chr(10).join(f"    case {a:#x}ULL: fn_{a:x}(s); return;" for a in translated)}
    default: fprintf(stderr, "atlas: no translation for guest code at %#lx\\n", (unsigned long)target); abort();
  }}
}}
void atlas_trap(atlas_state *s, uint64_t at, int kind) {{
  fprintf(stderr, "atlas: guest trap %d at %#lx\\n", kind, (unsigned long)at); abort();
}}
#include "atlas_syscall.inc"
int main(int argc, char **argv, char **envp) {{
  static atlas_state st;
  atlas_state *s = &st;
  s->mem = mmap(NULL, {GUEST_SIZE:#x}ULL, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (s->mem == MAP_FAILED) {{ perror("atlas: guest memory"); return 127; }}
  FILE *self = fopen("{request["binary"]}", "rb");
  if (!self) {{ perror("atlas: the original binary"); return 127; }}
  static const struct {{ uint64_t vaddr, memsize, offset, filesize; }} segs[] = {{
{chr(10).join(f"    {{{v:#x}ULL, {m:#x}ULL, {o:#x}ULL, {fsz:#x}ULL}}," for v, m, o, fsz in segs)}
  }};
  for (unsigned k = 0; k < sizeof segs / sizeof segs[0]; k++) {{
    if (segs[k].filesize) {{
      fseek(self, (long)segs[k].offset, SEEK_SET);
      if (fread(s->mem + segs[k].vaddr, 1, segs[k].filesize, self) != segs[k].filesize) return 127;
    }}
  }}
  fclose(self);
  atlas_guest_setup(s, argc, argv, envp);
  REG(uint32_t, {off["sp"]}) = atlas_guest_sp;
  atlas_call(s, {obj.entry & ~1:#x}ULL);
  return 0;
}}
void atlas_syscall(atlas_state *s) {{
  uint32_t number = REG(uint32_t, {off[conv["number"]]});
{tls_case}  atlas_do_syscall(s, number, {args}, &REG(uint32_t, {off[conv["result"]]}));
}}
"""
    out = request["out"]
    with open(out + ".main.c", "w") as f:
        f.write(c)
    print(json.dumps({"generated": out + ".main.c", "translated": len(translated), "entry": hex(obj.entry)}))


if __name__ == "__main__":
    main()
