"""Verified rewrites in a linked program (link.py): a function's C, checked byte for byte against the original,
takes the place of its mechanical translation.

A rewrite is compiled for the host as it was verified (the toolchain's flags, Ghidra's prelude), then renamed so
its symbol cannot clash with the C library's. On an x86-64 host running an x86-64 guest the calling conventions are
the same, so the translations call a rewrite through the import trampoline, and a rewrite calls the program's other
functions through a stub per callee that hands its argument registers to the guest state and runs the callee's
translation (or rewrite). A rewrite is used only when every symbol it needs is a function: one of the binary's
(resolved by name to its address) or the C library's. One reading or writing a global of the original stays a
translation for now (its symbol would need the global's address in the original's image).
"""

import os
import subprocess


def compile_rewrite(rewrite, work, cc="gcc"):
    """Compiles one rewrite to an object; returns its path and the symbols it leaves undefined."""
    obj = os.path.join(work, f"rewrite_{rewrite['address']:x}.o")
    src = os.path.join(work, f"rewrite_{rewrite['address']:x}.c")
    with open(src, "w") as f:
        f.write(rewrite["source"])
    subprocess.run([cc, *rewrite["flags"], "-fPIE", "-c", src, "-o", obj], check=True, capture_output=True)
    listed = subprocess.run(["nm", "-u", obj], check=True, capture_output=True, text=True).stdout
    undefined = [line.split()[-1] for line in listed.splitlines() if line.strip()]
    return obj, undefined


def host_library_functions():
    """The C library's and the maths library's exported functions on this host."""
    out = set()
    for lib in ("/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libm.so.6"):
        if not os.path.exists(lib):
            continue
        listed = subprocess.run(["nm", "-D", "--defined-only", lib], capture_output=True, text=True).stdout
        for line in listed.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] in "TtWiI":
                out.add(parts[2].split("@")[0])
    return out


def prepare(rewrites, functions, work):
    """Which rewrites can be linked, and how.

    rewrites: [{"address": int, "name": str, "source": str, "flags": [str]}]; functions: the binary's functions by
    name (labels and name hypotheses) to their address. Returns (usable, skipped): usable entries carry the object,
    the renamed symbol and the callees to stub (name to address); skipped ones the reason.
    """
    library = host_library_functions()
    usable, skipped = [], []
    for r in rewrites:
        try:
            obj, undefined = compile_rewrite(r, work)
        except subprocess.CalledProcessError as error:
            skipped.append({"address": r["address"], "reason": f"does not compile for the host: {error.stderr[:200]}"})
            continue
        callees, missing = {}, []
        for sym in undefined:
            if sym in functions:
                callees[sym] = functions[sym]
            elif sym.startswith("FUN_") and all(c in "0123456789abcdefABCDEF" for c in sym[4:]):
                callees[sym] = int(sym[4:], 16)
            elif sym in library or sym.startswith("_GLOBAL_OFFSET_TABLE_"):
                continue
            else:
                missing.append(sym)
        if missing:
            skipped.append({"address": r["address"], "reason": f"needs data of the original: {', '.join(missing[:5])}"})
            continue
        # The rewrite's own symbol renamed, so a rewrite named like a C library function cannot shadow it.
        symbol = f"atlas_rewrite_{r['address']:x}"
        renamed = obj[:-2] + ".renamed.o"
        subprocess.run(["objcopy", "--redefine-sym", f"{r['name']}={symbol}", obj, renamed], check=True)
        usable.append({"address": r["address"], "object": renamed, "symbol": symbol, "callees": callees})
    return usable, skipped
