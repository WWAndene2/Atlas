"""The original file built into a linked program (shared by the linkers): its bytes are included at compile time
with the assembler's .incbin, under the symbol atlas_original, so the program reads its segments from itself and
does not depend on where the original was when it runs (moved, deleted, or a temporary extract of an .apk).
"""


def embed_original(path):
    """C source declaring `atlas_original`, the bytes of the file at `path`."""
    # Each byte of the path an octal escape, read by the assembler: no character of it can end either string.
    name = "".join(f"\\\\{b:03o}" for b in path.encode())
    return (f'__asm__(".section .rodata\\n.balign 16\\natlas_original:\\n.incbin \\"{name}\\"\\n.previous");\n'
            "extern const unsigned char atlas_original[];\n")
