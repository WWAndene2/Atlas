"""Static recompilation: one function's machine code to C, through VEX (the IR of angr's lifter, pyvex), so one
translator serves every architecture VEX decodes (x86, x86-64, ARM, ARM64, MIPS, PowerPC).

argv[1]: request JSON {"arch": archinfo name, "binary"?: path, "functions": [{"address": int, "code": hex}]}
(with the binary, angr's CFG resolves jump tables so their targets become blocks of the translation)
stdout: one JSON line per function: {"address": "0x..", "c": str} or {"address": "0x..", "unsupported": str}

The C works on a guest state laid out as VEX lays it (registers at their VEX offsets in `s->r`), and on memory
through the runtime's load and store macros (src/tools/vex/atlas_lift.h), which apply the guest's byte order. Each
function is one `switch` over its block addresses inside one loop (a switch per jump made compiles take an hour on
large games, seen on a 3DS title); a call goes through atlas_call (the runtime dispatches to the callee's
translation, or reports a missing one), a return leaves the function. Whatever the translator does not handle (an
IR operation, a helper, a jump kind) makes the function unsupported, with the reason, rather than wrong.
"""

import json
import sys

import archinfo
import pyvex


# Kinds handed to atlas_trap.
TRAPS = {"Ijk_SigFPE_IntDiv": 1, "Ijk_SigFPE_IntOvf": 1, "Ijk_SigTRAP": 2, "Ijk_SigILL": 3, "Ijk_SigSEGV": 4}


# Load and store macro suffixes by IR type (atlas_lift.h).
MEMORY = {"Ity_I8": "8", "Ity_I16": "16", "Ity_I32": "32", "Ity_I64": "64", "Ity_F32": "F32", "Ity_F64": "F64",
          "Ity_V128": "V128"}


class Unsupported(Exception):
    pass


CTYPE = {"Ity_I1": "uint8_t", "Ity_I8": "uint8_t", "Ity_I16": "uint16_t", "Ity_I32": "uint32_t",
         "Ity_I64": "uint64_t", "Ity_I128": "unsigned __int128", "Ity_F32": "float", "Ity_F64": "double",
         "Ity_V128": "unsigned __int128"}
# Floating-point and vector operations, implemented in atlas_lift.h under the operation's own name: the lane
# operations of SSE (Add64F0x2...) on the low lane, comparisons, conversions with VEX's rounding-mode argument.
RUNTIME_OPS = {
    "Iop_AndV128": "atlas_and_v128", "Iop_OrV128": "atlas_or_v128", "Iop_XorV128": "atlas_xor_v128",
    "Iop_NotV128": "atlas_not_v128", "Iop_64UtoV128": "atlas_64uto_v128", "Iop_32UtoV128": "atlas_32uto_v128",
    "Iop_V128to64": "atlas_v128to64", "Iop_V128HIto64": "atlas_v128hito64", "Iop_64HLtoV128": "atlas_64hlto_v128",
    "Iop_SetV128lo64": "atlas_setv128lo64", "Iop_SetV128lo32": "atlas_setv128lo32", "Iop_V128to32": "atlas_v128to32",
    "Iop_Add64F0x2": "atlas_add64f0x2", "Iop_Sub64F0x2": "atlas_sub64f0x2", "Iop_Mul64F0x2": "atlas_mul64f0x2",
    "Iop_Div64F0x2": "atlas_div64f0x2", "Iop_Sqrt64F0x2": "atlas_sqrt64f0x2",
    "Iop_CmpLE64F0x2": "atlas_cmple64f0x2", "Iop_CmpLT64F0x2": "atlas_cmplt64f0x2",
    "Iop_CmpEQ64F0x2": "atlas_cmpeq64f0x2", "Iop_CmpUN64F0x2": "atlas_cmpun64f0x2",
    "Iop_CmpF64": "atlas_cmpf64", "Iop_I64StoF64": "atlas_i64stof64", "Iop_F64toI64S": "atlas_f64toi64s",
    "Iop_F64toI32S": "atlas_f64toi32s", "Iop_I32StoF64": "atlas_i32stof64", "Iop_F32toF64": "atlas_f32tof64",
    "Iop_F64toF32": "atlas_f64tof32", "Iop_AddF64": "atlas_addf64", "Iop_SubF64": "atlas_subf64",
    "Iop_MulF64": "atlas_mulf64", "Iop_DivF64": "atlas_divf64", "Iop_SqrtF64": "atlas_sqrtf64",
    "Iop_ReinterpF64asI64": "atlas_reinterp_f64_i64", "Iop_ReinterpI64asF64": "atlas_reinterp_i64_f64",
    "Iop_ReinterpF32asI32": "atlas_reinterp_f32_i32", "Iop_ReinterpI32asF32": "atlas_reinterp_i32_f32",
}
SIGNED = {"8": "int8_t", "16": "int16_t", "32": "int32_t", "64": "int64_t"}
UNSIGNED = {"1": "uint8_t", "8": "uint8_t", "16": "uint16_t", "32": "uint32_t", "64": "uint64_t",
            "128": "unsigned __int128"}


def binop(op, a, b):
    import re
    name = op[len("Iop_"):]
    m = re.fullmatch(r"(Add|Sub|Mul|And|Or|Xor)(8|16|32|64)", name)
    if m:
        sym = {"Add": "+", "Sub": "-", "Mul": "*", "And": "&", "Or": "|", "Xor": "^"}[m[1]]
        return f"({UNSIGNED[m[2]]})({a} {sym} {b})"
    m = re.fullmatch(r"(Shl|Shr|Sar)(8|16|32|64)", name)
    if m:
        t = UNSIGNED[m[2]]
        if m[1] == "Sar":
            return f"({t})(({SIGNED[m[2]]}){a} >> ({b} & {int(m[2]) - 1}))"
        return f"({t})({a} {'<<' if m[1] == 'Shl' else '>>'} ({b} & {int(m[2]) - 1}))"
    m = re.fullmatch(r"Cmp(EQ|NE)(8|16|32|64)", name) or re.fullmatch(r"CasCmp(EQ|NE)(8|16|32|64)", name) \
        or re.fullmatch(r"ExpCmp(NE)(8|16|32|64)", name)
    if m:
        return f"(uint8_t)({a} {'==' if m[1] == 'EQ' else '!='} {b})"
    m = re.fullmatch(r"Cmp(LT|LE)(8|16|32|64)(S|U)", name)
    if m:
        t = SIGNED[m[2]] if m[3] == "S" else UNSIGNED[m[2]]
        return f"(uint8_t)(({t}){a} {'<' if m[1] == 'LT' else '<='} ({t}){b})"
    m = re.fullmatch(r"Mull(S|U)(8|16|32|64)", name)
    if m:
        w = int(m[2])
        t = (SIGNED if m[1] == "S" else UNSIGNED)[m[2]]
        wide = {8: "16", 16: "32", 32: "64", 64: "128"}[w]
        wt = "__int128" if (wide == "128" and m[1] == "S") else (SIGNED.get(wide) if m[1] == "S" else UNSIGNED[wide])
        return f"({UNSIGNED[wide]})(({wt})({t}){a} * ({wt})({t}){b})"
    m = re.fullmatch(r"(\d+)HLto(\d+)", name)
    if m:
        return f"(({UNSIGNED[m[2]]}){a} << {m[1]} | ({UNSIGNED[m[2]]}){b})"
    m = re.fullmatch(r"DivMod(S|U)(64|128)to(32|64)", name)
    if m:
        half = int(m[3])
        wt = ("__int128" if m[2] == "128" else "int64_t") if m[1] == "S" else UNSIGNED[m[2]]
        dt = SIGNED[m[3]] if m[1] == "S" else UNSIGNED[m[3]]
        return (f"({UNSIGNED[m[2]]})((({UNSIGNED[m[2]]})({UNSIGNED[m[3]]})(({wt}){a} % ({dt}){b}) << {half}) "
                f"| ({UNSIGNED[m[3]]})(({wt}){a} / ({dt}){b}))")
    m = re.fullmatch(r"Div(S|U)(32|64)", name)
    if m:
        t = (SIGNED if m[1] == "S" else UNSIGNED)[m[2]]
        return f"({UNSIGNED[m[2]]})(({t}){a} / ({t}){b})"
    raise Unsupported(f"operation {op}")


def unop(op, a):
    import re
    name = op[len("Iop_"):]
    m = re.fullmatch(r"(\d+)(U|S)to(\d+)", name)
    if m:
        src = (SIGNED if m[2] == "S" and m[1] != "1" else UNSIGNED)[m[1]]
        return f"({UNSIGNED[m[3]]})({src}){a}"
    m = re.fullmatch(r"(\d+)to(\d+)", name)
    if m:
        if m[2] == "1":
            return f"(uint8_t)({a} & 1)"
        return f"({UNSIGNED[m[2]]}){a}"
    m = re.fullmatch(r"(\d+)HIto(\d+)", name)
    if m:
        return f"({UNSIGNED[m[2]]})({a} >> {m[2]})"
    m = re.fullmatch(r"Not(1|8|16|32|64)", name)
    if m:
        return f"(uint8_t)!{a}" if m[1] == "1" else f"({UNSIGNED[m[1]]})~{a}"
    m = re.fullmatch(r"(Clz|Ctz)(32|64)", name)
    if m:
        f = {"Clz": "__builtin_clz", "Ctz": "__builtin_ctz"}[m[1]] + ("ll" if m[2] == "64" else "")
        return f"({UNSIGNED[m[2]]})({a} ? {f}({a}) : {m[2]})"
    raise Unsupported(f"operation {op}")


class Function:
    def __init__(self, arch, address, code, targets=()):
        self.arch, self.address, self.code = arch, address, bytes.fromhex(code)
        # Block starts known otherwise: the targets of the function's jump tables (resolved by angr's CFG).
        self.targets = [t for t in targets if address <= t < address + len(self.code)]
        self.end = address + len(self.code)
        self.lines = []
        self.blocks = {}

    def reg(self, offset, ty):
        return f"REG({CTYPE[ty]}, {offset})"

    def expr(self, e, tmps):
        if isinstance(e, pyvex.expr.RdTmp):
            return f"t{e.tmp}"
        if isinstance(e, pyvex.expr.Const):
            v = e.con.value
            if isinstance(v, float):
                import struct as st_
                if e.con.type == "Ity_F32":
                    return f"atlas_reinterp_i32_f32({st_.unpack('<I', st_.pack('<f', v))[0]}U)"
                return f"atlas_reinterp_i64_f64({st_.unpack('<Q', st_.pack('<d', v))[0]}ULL)"
            if e.con.type == "Ity_V128":
                # VEX's V128 constant is 16 bits, one per byte: set means 0xff.
                full = sum(0xFF << (8 * i) for i in range(16) if int(v) >> i & 1)
                return f"(((unsigned __int128){full >> 64:#x}ULL << 64) | {full & (2**64 - 1):#x}ULL)"
            return f"((uint64_t){int(v)}ULL)"
        if isinstance(e, pyvex.expr.Get):
            if e.ty not in CTYPE:
                raise Unsupported(f"register of type {e.ty}")
            return self.reg(e.offset, e.ty)
        if isinstance(e, pyvex.expr.Load):
            name = MEMORY.get(e.ty)
            if name is None:
                raise Unsupported(f"load of {e.ty}")
            return f"LOAD{name}({self.expr(e.addr, tmps)})"
        if isinstance(e, (pyvex.expr.Binop, pyvex.expr.Unop, pyvex.expr.Triop)) and e.op in RUNTIME_OPS:
            return f"{RUNTIME_OPS[e.op]}({', '.join(self.expr(a, tmps) for a in e.args)})"
        if isinstance(e, pyvex.expr.Binop):
            return binop(e.op, *(self.expr(a, tmps) for a in e.args))
        if isinstance(e, pyvex.expr.Unop):
            return unop(e.op, self.expr(e.args[0], tmps))
        if isinstance(e, pyvex.expr.ITE):
            return f"({self.expr(e.cond, tmps)} ? {self.expr(e.iftrue, tmps)} : {self.expr(e.iffalse, tmps)})"
        if isinstance(e, pyvex.expr.CCall):
            args = ", ".join(self.expr(a, tmps) for a in e.args)
            return f"{e.cee.name}({args})"
        raise Unsupported(f"expression {type(e).__name__}")

    def lift_block(self, addr):
        try:
            irsb = pyvex.lift(self.code[addr - self.address:], addr, self.arch, opt_level=1)
        except pyvex.PyVEXError as error:
            raise Unsupported(f"undecodable at {addr:#x}: {error}")
        if irsb.size == 0 or irsb.jumpkind == "Ijk_NoDecode":
            raise Unsupported(f"undecodable at {addr:#x}")
        return irsb

    def translate(self):
        todo, seen = [self.address, *self.targets], set()
        out = []
        while todo:
            a = todo.pop()
            if a in seen or not (self.address <= a < self.end):
                continue
            seen.add(a)
            irsb = self.lift_block(a)
            body = [f"    case {a:#x}ULL: {{"]
            tmps = irsb.tyenv.types
            for i, ty in enumerate(tmps):
                if ty not in CTYPE:
                    raise Unsupported(f"temporary of type {ty}")
            if tmps:
                body.append("      " + " ".join(f"{CTYPE[ty]} t{i};" for i, ty in enumerate(tmps)))
            for st in irsb.statements:
                if isinstance(st, (pyvex.stmt.IMark, pyvex.stmt.NoOp, pyvex.stmt.AbiHint)):
                    continue
                if isinstance(st, pyvex.stmt.WrTmp):
                    body.append(f"      t{st.tmp} = {self.expr(st.data, tmps)};")
                elif isinstance(st, pyvex.stmt.Put):
                    ty = st.data.result_type(irsb.tyenv)
                    if ty not in CTYPE:
                        raise Unsupported(f"register write of {ty}")
                    body.append(f"      {self.reg(st.offset, ty)} = {self.expr(st.data, tmps)};")
                elif isinstance(st, pyvex.stmt.Store):
                    ty = st.data.result_type(irsb.tyenv)
                    if ty not in MEMORY:
                        raise Unsupported(f"store of {ty}")
                    body.append(f"      STORE{MEMORY[ty]}({self.expr(st.addr, tmps)}, {self.expr(st.data, tmps)});")
                elif isinstance(st, pyvex.stmt.Exit):
                    if st.jumpkind.startswith("Ijk_Sig"):
                        # A trap the guest raises (division by zero, ud2): the program's atlas_trap decides.
                        kind = TRAPS.get(st.jumpkind, 0)
                        body.append(f"      if ({self.expr(st.guard, tmps)}) {{ atlas_trap(s, {a:#x}ULL, {kind}); return; }}")
                        continue
                    if st.jumpkind != "Ijk_Boring":
                        raise Unsupported(f"conditional exit {st.jumpkind}")
                    target = st.dst.value
                    todo.append(target)
                    inside = self.address <= target < self.end
                    jump = f"pc = {target:#x}ULL; continue;" if inside else f"atlas_call(s, {target:#x}ULL); return;"
                    body.append(f"      if ({self.expr(st.guard, tmps)}) {{ {jump} }}")
                else:
                    raise Unsupported(f"statement {type(st).__name__}")
            nxt = irsb.next
            constant = nxt.con.value if isinstance(nxt, pyvex.expr.Const) else None
            if irsb.jumpkind == "Ijk_Ret":
                body.append("      return;")
            elif irsb.jumpkind == "Ijk_Call":
                target = f"{constant:#x}ULL" if constant is not None else self.expr(nxt, tmps)
                after = a + irsb.size
                # The callee returns to the instruction after the call (the return address the call pushed or the
                # link register it set is part of the state the translation already wrote).
                body.append(f"      atlas_call(s, {target}); pc = {after:#x}ULL; continue;")
                todo.append(after)
            elif irsb.jumpkind == "Ijk_Boring":
                if constant is not None and self.address <= constant < self.end:
                    todo.append(constant)
                    body.append(f"      pc = {constant:#x}ULL; continue;")
                elif constant is not None:
                    body.append(f"      atlas_call(s, {constant:#x}ULL); return;  /* tail jump */")
                else:
                    # A jump through a register: a switch table inside the function, or a tail call elsewhere.
                    body.append(f"      pc = {self.expr(nxt, tmps)}; continue;")
            elif irsb.jumpkind.startswith("Ijk_Sig"):
                body.append(f"      atlas_trap(s, {a:#x}ULL, {TRAPS.get(irsb.jumpkind, 0)}); return;")
            else:
                raise Unsupported(f"jump kind {irsb.jumpkind}")
            body.append("    }")
            out.append("\n".join(body))
        name = f"fn_{self.address:x}"
        return (f"void {name}(atlas_state *s) {{\n  uint64_t pc = {self.address:#x}ULL;\n  for (;;) {{\n"
                f"    switch (pc) {{\n" + "\n".join(out) + "\n    default: atlas_call(s, pc); return;\n    }\n  }\n}\n")


def jump_table_targets(binary):
    """Every target of an indirect jump angr's CFG resolves (switch tables), from the binary as loaded at 0 if
    position-independent, as the graph has it."""
    import angr
    import logging

    logging.getLogger("angr").setLevel(logging.ERROR)
    proj = angr.Project(binary, auto_load_libs=False, main_opts={"base_addr": 0})
    cfg = proj.analyses.CFGFast(resolve_indirect_jumps=True, normalize=True)
    out = set()
    for jump in cfg.indirect_jumps.values():
        out.update(jump.resolved_targets or ())
    return out


def main():
    request = json.load(open(sys.argv[1]))
    arch = archinfo.arch_from_id(request["arch"])
    targets = sorted(jump_table_targets(request["binary"])) if request.get("binary") else []
    for f in request["functions"]:
        try:
            c = Function(arch, f["address"], f["code"], targets).translate()
            print(json.dumps({"address": hex(f["address"]), "c": c}), flush=True)
        except Unsupported as reason:
            print(json.dumps({"address": hex(f["address"]), "unsupported": str(reason)}), flush=True)
        except Exception as error:  # a translator bug is reported per function, not a crash of the run
            print(json.dumps({"address": hex(f["address"]), "unsupported": f"translator error: {error}"[:300]}),
                  flush=True)


if __name__ == "__main__":
    main()
