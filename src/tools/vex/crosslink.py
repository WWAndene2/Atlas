"""Links a binary's translations into a program when the guest's CPU is not the host's (an ARM game run on a PC).

Unlike link.py (guest = host, the C library called natively), the guest here is self-contained: a statically linked
ELF whose own code, C library included, is translated. Guest memory is a block of host memory, and a guest address
a is reached at mem + a (the runtime's flat mapping), so nothing of the host leaks in. What the guest asks of its
operating system is served by atlas_syscall, which reads the system-call number and arguments from the guest
registers and carries out the common Linux calls on the guest's memory (atlas_syscall.inc). This is the console case
in miniature: the code is faithful, the platform's services are emulated.

Only the register layout and system-call convention are architecture-specific (CONVENTIONS); the rest is shared.

Request, a JSON file named on the command line: {"arch", "endness", "binary": path of the original (built into the
program), "lifted": [paths of the translations' C], "translated": [graph addresses], "base": where a
position-independent image is mapped, "runtime": directory of atlas_lift.h, "out": path of the executable, "profile": the platform the guest runs on,
"linux" (the default: Linux system calls, atlas_syscall.inc) or a console's (console/<profile>.inc on the console
kernel's core, console/kernel.inc: "ctr" for the 3DS, "bare" for a machine with no operating system), "devices":
[low, high] (optional: the window of hardware registers, accesses in it going to the profile's devices,
console/devices.inc)}
stdout: {"executable": path, "translated": int, "entry": hex}
"""

import json
import logging
import subprocess
import sys

import archinfo
import cle

from embed import embed_original

# Per architecture: the registers a Linux system call reads (number, then up to six arguments, then where the
# result goes), as archinfo names them. ARM EABI: r7 holds the number, r0-r5 the arguments, r0 the result.
CONVENTIONS = {
    "ARMEL": {"number": "r7", "args": ["r0", "r1", "r2", "r3", "r4", "r5"], "result": "r0"},
    "ARMHF": {"number": "r7", "args": ["r0", "r1", "r2", "r3", "r4", "r5"], "result": "r0"},
}

GUEST_SIZE = 0x40000000  # 1 GiB of guest memory
# The guest's memory layout (atlas_syscall.inc): mmap's arena from 0x20000000, then 8 MiB of stack below the top.
GUEST_MMAP, GUEST_TOP = 0x20000000, 0x3F000000
GUEST_STACK_LOW = GUEST_TOP - 0x800000


def main():
    request = json.load(open(sys.argv[1]))
    arch = archinfo.arch_from_id(request["arch"], request.get("endness", "any"))
    if arch.name not in CONVENTIONS:
        raise SystemExit(f"no system-call convention for {arch.name} guests")
    conv = CONVENTIONS[arch.name]
    off = {r: arch.registers[r][0] for r in [conv["number"], conv["result"], *conv["args"], "sp"]}
    logging.getLogger("cle").setLevel(logging.ERROR)  # "base_addr ... not PIC" for a fixed-address image
    loader = cle.Loader(request["binary"], auto_load_libs=False, main_opts={"base_addr": 0})
    obj = loader.main_object
    # base: where a position-independent image is mapped (the translations were made at it, lift.py's "base").
    base = int(request.get("base", 0))
    translated = [int(a) + base for a in request["translated"]]
    segs = [(s.vaddr + base, s.memsize, s.offset, s.filesize) for s in obj.segments]
    image_end = (max(v + m for v, m, _, _ in segs) + 0xFFF) & ~0xFFF
    if image_end > GUEST_MMAP:
        raise SystemExit(f"the image ends at {image_end:#x}, past the guest's mmap arena at {GUEST_MMAP:#x}")
    layout = {"ATLAS_GUEST_BRK": image_end, "ATLAS_GUEST_MMAP": GUEST_MMAP, "ATLAS_GUEST_TOP": GUEST_TOP,
              "ATLAS_GUEST_STACK_LOW": GUEST_STACK_LOW}
    tls = arch.registers["tpidruro"][0] if "tpidruro" in arch.registers else None
    # The registers VEX expects at their defaults when a guest starts (as link.py sets them), but sp and pc.
    defaults = [
        (arch.registers[n][0], arch.registers[n][1], v)
        for n, v, *_ in arch.default_register_values
        if n in arch.registers and n not in ("sp", "pc")
    ]
    args = ", ".join(f"REG(uint32_t, {off[r]})" for r in conv["args"])
    # ARM's set_tls (0xf0005): the thread pointer is a guest register (TPIDRURO), not host state.
    tls_case = (
        f"  if (number == 0xf0005) {{ REG(uint32_t, {tls}) = REG(uint32_t, {off[conv['args'][0]]}); "
        f"REG(uint32_t, {off[conv['result']]}) = 0; return; }}\n"
        if tls is not None
        else ""
    )
    nl = "\n"
    profile = request.get("profile", "linux")
    if profile == "linux":
        platform = '#include "atlas_syscall.inc"'
        setup = f"  atlas_guest_setup(s, argc, argv, envp);\n  REG(uint32_t, {off['sp']}) = atlas_guest_sp;"
        serve = f"""  uint32_t number = REG(uint32_t, {off[conv["number"]]});
{tls_case}  atlas_do_syscall(s, number, {args}, &REG(uint32_t, {off[conv["result"]]}));"""
    elif profile == "ctr":
        # A 3DS title: no argument vector or environment, its stack and thread storage at the console's addresses.
        regs = ", ".join(str(arch.registers[f"r{k}"][0]) for k in range(6))
        platform = (f"static const uint32_t ctr_reg[6] = {{{regs}}};\n"
                    f"#define CTR_TLS_REG {tls}\n#define CTR_SP_REG {off['sp']}\n"
                    '#include "console/kernel.inc"\n#include "console/threads.inc"\n#include "console/frames.inc"\n'
                    '#include "console/ctr.inc"\n#include "console/ctr_gsp.inc"')
        setup = f"  (void)argc; (void)argv; (void)envp;\n  ctr_setup(s);\n  REG(uint32_t, {off['sp']}) = CTR_STACK_TOP;"
        serve = "  ctr_syscall(s);"
    elif profile == "bare":
        # No operating system: the program starts at its entry with a stack, and owns the machine.
        platform = (f"#define BARE_R0 {arch.registers['r0'][0]}\n#define BARE_R1 {arch.registers['r1'][0]}\n"
                    '#include "console/kernel.inc"\n#include "console/bare.inc"')
        setup = f"  (void)argc; (void)argv; (void)envp;\n  bare_setup(s);\n  REG(uint32_t, {off['sp']}) = {GUEST_TOP:#x};"
        serve = "  bare_syscall(s);"
    else:
        raise SystemExit(f"no platform profile {profile!r} (linux, ctr, bare)")
    # The hardware registers' window: every translation is compiled to send accesses in it to the devices.
    devices = request.get("devices")
    flags = []
    if devices is not None:
        low, high = (int(v) for v in devices)
        flags = [f"-DATLAS_DEVICE_LOW={low:#x}ULL", f"-DATLAS_DEVICE_HIGH={high:#x}ULL"]
        if profile == "linux":
            platform += '\n#include "console/kernel.inc"\nstatic void atlas_devices_log(void) __attribute__((constructor));\n' \
                        "static void atlas_devices_log(void) { atexit(console_unserved_write); }"
        platform += '\n#include "console/devices.inc"'

    c = f"""#include "atlas_lift.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
{nl.join(f"#define {k} {v:#x}ULL" for k, v in layout.items())}
{nl.join(f"void fn_{a:x}(atlas_state *s);" for a in translated)}
void atlas_call(atlas_state *s, uint64_t target) {{
  switch (target) {{
{nl.join(f"    case {a:#x}ULL: fn_{a:x}(s); return;" for a in translated)}
    default: fprintf(stderr, "atlas: no translation for guest code at %#lx\\n", (unsigned long)target); abort();
  }}
}}
void atlas_trap(atlas_state *s, uint64_t at, int kind) {{
  fprintf(stderr, "atlas: guest trap %d at %#lx\\n", kind, (unsigned long)at); abort();
}}
{platform}
{embed_original(request["binary"])}
int main(int argc, char **argv, char **envp) {{
  static atlas_state st;
  atlas_state *s = &st;
  s->mem = mmap(NULL, {GUEST_SIZE:#x}ULL, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (s->mem == MAP_FAILED) {{ perror("atlas: guest memory"); return 127; }}
  static const struct {{ uint64_t vaddr, memsize, offset, filesize; }} segs[] = {{
{nl.join(f"    {{{v:#x}ULL, {m:#x}ULL, {o:#x}ULL, {fsz:#x}ULL}}," for v, m, o, fsz in segs)}
  }};
  for (unsigned k = 0; k < sizeof segs / sizeof segs[0]; k++) {{
    if (segs[k].filesize) memcpy(s->mem + segs[k].vaddr, atlas_original + segs[k].offset, segs[k].filesize);
  }}
{nl.join(f"  memcpy(s->r + {o}, &(uint64_t){{{v:#x}ULL}}, {n});" for o, n, v in defaults)}
{setup}
  atlas_call(s, {(obj.entry + base) & ~1:#x}ULL);
  return 0;
}}
void atlas_syscall(atlas_state *s) {{
{serve}
}}
"""
    out = request["out"]
    with open(out + ".main.c", "w") as f:
        f.write(c)
    subprocess.run(["gcc", "-O1", "-w", *flags, "-I", request["runtime"], *request["lifted"], out + ".main.c", "-o", out,
                    "-lm"], check=True)
    print(json.dumps({"executable": out, "translated": len(translated), "entry": hex(obj.entry + base)}))


if __name__ == "__main__":
    main()
