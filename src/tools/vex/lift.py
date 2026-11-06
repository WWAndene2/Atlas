"""Static recompilation: one function's machine code to C, through VEX (the IR of angr's lifter, pyvex), so one
translator serves every architecture VEX decodes (x86, x86-64, ARM, ARM64, MIPS, PowerPC).

argv[1]: request JSON {"arch": archinfo name, "endness"?: "Iend_LE" | "Iend_BE", "binary"?: path,
                       "functions": [{"address": int, "code": hex, "thumb"?: bool}]}
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
# VEX helpers with side effects (Dirty statements) that the runtime (atlas_lift.h) implements, and whether each takes
# the translation's state first (one that reaches guest memory does: its addresses are guest addresses).
DIRTY = {"amd64g_dirtyhelper_FINIT": False, "amd64g_dirtyhelper_loadF80le": True,
         "amd64g_dirtyhelper_storeF80le": True}

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
    "Iop_InterleaveLO64x2": "atlas_interleavelo64x2", "Iop_InterleaveHI64x2": "atlas_interleavehi64x2",
    "Iop_InterleaveLO32x4": "atlas_interleavelo32x4", "Iop_InterleaveHI32x4": "atlas_interleavehi32x4",
    **{f"Iop_{op}{w}x{128 // w}": f"atlas_{op.lower()}{w}x{128 // w}" for op in ("Add", "Sub", "CmpEQ")
       for w in (8, 16, 32, 64)},
    "Iop_ShlN64x2": "atlas_shln64x2", "Iop_ShrN64x2": "atlas_shrn64x2",
    "Iop_PRemF64": "atlas_premf64", "Iop_PRemC3210F64": "atlas_premc3210f64",
    "Iop_AtanF64": "atlas_atanf64", "Iop_ScaleF64": "atlas_scalef64", "Iop_Yl2xF64": "atlas_yl2xf64",
    "Iop_Yl2xp1F64": "atlas_yl2xp1f64", "Iop_SinF64": "atlas_sinf64", "Iop_CosF64": "atlas_cosf64",
    "Iop_RoundF64toInt": "atlas_round", "Iop_2xm1F64": "atlas_2xm1f64", "Iop_PRem1F64": "atlas_prem1f64",
    "Iop_PRem1C3210F64": "atlas_prem1c3210f64",
    "Iop_MAddF64": "atlas_maddf64", "Iop_MSubF64": "atlas_msubf64", "Iop_ZeroHI64ofV128": "atlas_zerohi64ofv128",
    "Iop_Reverse8sIn64_x2": "atlas_reverse8sin64x2",
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
    m = re.fullmatch(r"CmpORD(32|64)(S|U)", name)
    if m:
        # PowerPC's compare: 8 when less, 4 when greater, 2 when equal.
        t = (SIGNED if m[2] == "S" else UNSIGNED)[m[1]]
        return f"({UNSIGNED[m[1]]})((({t}){a} < ({t}){b}) ? 8 : (({t}){a} > ({t}){b}) ? 4 : 2)"
    m = re.fullmatch(r"DivMod(S|U)32to32", name)
    if m:
        t = (SIGNED if m[1] == "S" else UNSIGNED)["32"]
        return f"(((uint64_t)(uint32_t)(({t}){a} % ({t}){b}) << 32) | (uint32_t)(({t}){a} / ({t}){b}))"
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
    m = re.fullmatch(r"(Clz|Ctz)Nat(32|64)", name)
    if m:
        f = {"Clz": "__builtin_clz", "Ctz": "__builtin_ctz"}[m[1]] + ("ll" if m[2] == "64" else "")
        return f"({UNSIGNED[m[2]]})({a} ? {f}({a}) : {m[2]})"
    m = re.fullmatch(r"(Neg|Abs)F(32|64)", name)
    if m:
        return f"(-({a}))" if m[1] == "Neg" else f"{'fabs' if m[2] == '64' else 'fabsf'}({a})"
    m = re.fullmatch(r"(Clz|Ctz)(32|64)", name)
    if m:
        f = {"Clz": "__builtin_clz", "Ctz": "__builtin_ctz"}[m[1]] + ("ll" if m[2] == "64" else "")
        return f"({UNSIGNED[m[2]]})({a} ? {f}({a}) : {m[2]})"
    raise Unsupported(f"operation {op}")


class Function:
    def __init__(self, arch, address, code, targets=(), thumb=False, memory=None):
        self.arch, self.address, self.code, self.thumb = arch, address, bytes.fromhex(code), thumb
        # The loaded binary, when given: a block is decoded from it, since an engine's code window can stop in the
        # middle of the function's last instruction (Ghidra's for Lua's 0x18190).
        self.memory = memory
        self.per_instruction = False
        # ARM: a jump's target carries the Thumb state in its low bit; blocks and the dispatch use the even address.
        self.mask = ~1 if arch.name.startswith("ARM") else ~0
        # Block starts known otherwise: the targets of the function's jump tables (resolved by angr's CFG).
        self.targets = [t for t in targets if address <= t < address + len(self.code)]
        self.end = address + len(self.code)
        self.lines = []
        self.blocks = {}

    def indexed(self, descr, ix, bias, tmps):
        """The offset of an element of a register array (x87's stack: the index wraps around nElems)."""
        size = {"Ity_F64": 8, "Ity_I8": 1, "Ity_I64": 8, "Ity_I32": 4}.get(descr.elemTy)
        if size is None:
            raise Unsupported(f"register array of {descr.elemTy}")
        return f"({descr.base} + (((int64_t)({self.expr(ix, tmps)}) + {bias}) & {descr.nElems - 1}) * {size})"

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
        if isinstance(e, pyvex.expr.GetI):
            return f"REG({CTYPE[e.descr.elemTy]}, {self.indexed(e.descr, e.ix, e.bias, tmps)})"
        if isinstance(e, pyvex.expr.Load):
            name = MEMORY.get(e.ty)
            if name is None:
                raise Unsupported(f"load of {e.ty}")
            return f"LOAD{name}({self.expr(e.addr, tmps)})"
        if isinstance(e, (pyvex.expr.Binop, pyvex.expr.Unop, pyvex.expr.Triop, pyvex.expr.Qop)) and e.op in RUNTIME_OPS:
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
            # Thumb code is lifted at its address with the low bit set, as VEX expects.
            data = self.code[addr - self.address:]
            if self.memory is not None:
                # As much as the loaded image holds from there (a load past a segment's end is refused).
                for size in (4096, 1024, 256, 64):
                    try:
                        data = self.memory.load(addr, size)
                        break
                    except KeyError:
                        continue
            # Thumb: VEX takes the odd address, and bytes_offset 1 for data that starts at the even one (as angr's
            # lifter passes them); with 0 it decodes from one byte before the instruction.
            irsb = pyvex.lift(data, addr | 1 if self.thumb else addr, self.arch, opt_level=1,
                              bytes_offset=1 if self.thumb else 0,
                              max_inst=1 if self.per_instruction else None)
        except pyvex.PyVEXError as error:
            raise Unsupported(f"undecodable at {addr:#x}: {error}")
        # A block whose first instruction does not decode is not code; one that decodes some instructions first and
        # then meets bytes that are not (a literal pool after a jump, padding) keeps them, ending in a trap there.
        if irsb.size == 0 or (irsb.jumpkind == "Ijk_NoDecode" and not any(
                isinstance(st, pyvex.stmt.IMark) for st in irsb.statements)):
            raise Unsupported(f"undecodable at {addr:#x}")
        return irsb

    def call(self, target, after):
        """A call: the callee should come back to `after`. A return that went elsewhere (hand-written assembly popping
        its caller's saved return address, a return that skips a level) is followed: to that address when it lies in
        this function, else by returning too, so each caller checks in turn until the one that expected it."""
        return (f"s->returned = {after:#x}ULL; ATLAS_CALL({target}); "
                f"if (s->returned != {after:#x}ULL && s->returned != ATLAS_RETURNED_ANY) {{ "
                f"if (s->returned >= {self.address:#x}ULL && s->returned < {self.end:#x}ULL) {{ pc = s->returned; continue; }} "
                f"return; }} pc = {after:#x}ULL; continue;")

    def thumb_branch(self, at):
        """The target of a Thumb-2 unconditional B.W (encoding T4) at `at`, or None if it is not one (ARM ARM:
        I1 = not (J1 xor S), I2 = not (J2 xor S), offset = SignExtend(S:I1:I2:imm10:imm11:0))."""
        try:
            data = self.memory.load(at, 4) if self.memory is not None else self.code[at - self.address:][:4]
        except KeyError:
            return None
        if len(data) < 4:
            return None
        hw1, hw2 = int.from_bytes(data[0:2], "little"), int.from_bytes(data[2:4], "little")
        if (hw1 & 0xF800) != 0xF000 or (hw2 & 0xD000) != 0x9000:
            return None
        sign, j1, j2 = (hw1 >> 10) & 1, (hw2 >> 13) & 1, (hw2 >> 11) & 1
        i1, i2 = 1 - (j1 ^ sign), 1 - (j2 ^ sign)
        offset = (sign << 24) | (i1 << 23) | (i2 << 22) | ((hw1 & 0x3FF) << 12) | ((hw2 & 0x7FF) << 1)
        if sign:
            offset -= 1 << 25
        return (at + 4 + offset) & self.mask

    def has_indirect_jump(self):
        """Whether a block reachable from the entry jumps through a register (a switch table)."""
        todo, seen = [self.address, *self.targets], set()
        while todo:
            a = todo.pop()
            if a in seen or not (self.address <= a < self.end):
                continue
            seen.add(a)
            try:
                irsb = self.lift_block(a)
            except Unsupported:
                continue  # the main pass decides what an undecodable block becomes
            if irsb.jumpkind == "Ijk_Boring" and not isinstance(irsb.next, pyvex.expr.Const):
                return True
            todo.extend(t & self.mask for t in irsb.constant_jump_targets)
            todo.append(a + irsb.size)
        return False

    def instruction_starts(self):
        """Every instruction address of the function by linear sweep (with per-instruction lifting)."""
        out, a = [], self.address
        while a < self.end:
            try:
                irsb = self.lift_block(a)
            except Unsupported:
                # Bytes that are not code (padding, data in the code): skipped one at a time.
                a += 1
                continue
            out.append(a)
            a += max(irsb.size, 1)
        return set(out)

    def translate(self):
        self.per_instruction = False
        # A switch table the CFG did not resolve would send control to an address with no block: in a function
        # with an indirect jump, every instruction starts a block (slower dispatch, but any target lands).
        extra = []
        if self.has_indirect_jump():
            self.per_instruction = True
            extra = self.instruction_starts()
        todo, seen = [self.address, *self.targets, *extra], set()
        optional = set(extra) - {self.address, *self.targets}
        out = []
        while todo:
            a = todo.pop()
            if a in seen or not (self.address <= a < self.end):
                continue
            seen.add(a)
            try:
                irsb = self.lift_block(a)
            except Unsupported as reason:
                if a in optional:
                    continue
                branch = self.thumb_branch(a) if self.thumb else None
                if branch is not None:
                    # A block that starts with a B.W VEX refuses (see thumb_branch): the jump alone.
                    inside = self.address <= branch < self.end
                    if inside:
                        todo.append(branch)
                    jump = f"pc = {branch:#x}ULL; continue;" if inside else f"atlas_call(s, {branch:#x}ULL); return;"
                    out.append(f"    case {a:#x}ULL: {jump}")
                    continue
                if str(reason).startswith("undecodable"):
                    # Reached only if the original would fault there too (ud2, padding after a noreturn call):
                    # a trap at run time, not a refused function.
                    out.append(f"    case {a:#x}ULL: atlas_trap(s, {a:#x}ULL, 3); return;")
                    continue
                raise
            mark = len(todo)
            try:
                body = [f"    case {a:#x}ULL: {{"]
                tmps = irsb.tyenv.types
                for i, ty in enumerate(tmps):
                    if ty not in CTYPE:
                        raise Unsupported(f"temporary of type {ty}")
                if tmps:
                    body.append("      " + " ".join(f"{CTYPE[ty]} t{i};" for i, ty in enumerate(tmps)))
                for st in irsb.statements:
                    if isinstance(st, pyvex.stmt.IMark):
                        last_mark = (st.addr, st.len)
                        continue
                    if isinstance(st, (pyvex.stmt.NoOp, pyvex.stmt.AbiHint)):
                        continue
                    if isinstance(st, pyvex.stmt.WrTmp):
                        body.append(f"      t{st.tmp} = {self.expr(st.data, tmps)};")
                    elif isinstance(st, pyvex.stmt.PutI):
                        if st.descr.nElems & (st.descr.nElems - 1):
                            raise Unsupported("register array not a power of two long")
                        body.append(f"      REG({CTYPE[st.descr.elemTy]}, "
                                    f"{self.indexed(st.descr, st.ix, st.bias, tmps)}) = {self.expr(st.data, tmps)};")
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
                    elif isinstance(st, pyvex.stmt.Dirty):
                        # A helper with side effects on the guest state (x87's fninit...): called as VEX would, with
                        # the guest state for GSPTR; the runtime implements only the helpers in DIRTY.
                        if st.cee.name not in DIRTY:
                            raise Unsupported(f"helper {st.cee.name}")
                        args = ", ".join("s->r" if isinstance(x, pyvex.expr.GSPTR) else self.expr(x, tmps)
                                         for x in st.args)
                        call = f"{st.cee.name}({'s, ' if DIRTY[st.cee.name] else ''}{args})"
                        if st.tmp != 0xFFFFFFFF:
                            call = f"t{st.tmp} = {call}"
                        guard = self.expr(st.guard, tmps)
                        body.append(f"      if ({guard}) {call};" if guard not in ("1", "((uint8_t)1)") else f"      {call};")
                    elif isinstance(st, pyvex.stmt.CAS):
                        # A compare-and-swap (x86's lock cmpxchg): a translated program runs on one thread, so the
                        # read, the comparison and the write in turn are the same. A double-width CAS is refused.
                        ty = irsb.tyenv.lookup(st.oldLo)
                        if st.oldHi != 0xFFFFFFFF or ty not in MEMORY:
                            raise Unsupported(f"compare-and-swap of {ty}{' pair' if st.oldHi != 0xFFFFFFFF else ''}")
                        addr = self.expr(st.addr, tmps)
                        body.append(f"      t{st.oldLo} = LOAD{MEMORY[ty]}({addr}); if (t{st.oldLo} == "
                                    f"{self.expr(st.expdLo, tmps)}) STORE{MEMORY[ty]}({addr}, {self.expr(st.dataLo, tmps)});")
                    elif isinstance(st, pyvex.stmt.LoadG):
                        # A guarded load (ARM's conditional loads): the converted value if the guard holds, else alt.
                        loaded = {"ILGop_Ident32": "LOAD32", "ILGop_Ident64": "LOAD64", "ILGop_16Uto32": "LOAD16",
                                  "ILGop_8Uto32": "LOAD8", "ILGop_16Sto32": "LOAD16", "ILGop_8Sto32": "LOAD8"}.get(st.cvt)
                        if loaded is None:
                            raise Unsupported(f"guarded load {st.cvt}")
                        value = f"{loaded}({self.expr(st.addr, tmps)})"
                        if st.cvt in ("ILGop_16Sto32", "ILGop_8Sto32"):
                            value = f"(uint32_t)(int{st.cvt[6:8].rstrip('S')}_t){value}"
                        body.append(f"      t{st.dst} = {self.expr(st.guard, tmps)} ? {value} : {self.expr(st.alt, tmps)};")
                    elif isinstance(st, pyvex.stmt.StoreG):
                        ty = st.data.result_type(irsb.tyenv)
                        if ty not in MEMORY:
                            raise Unsupported(f"guarded store of {ty}")
                        body.append(f"      if ({self.expr(st.guard, tmps)}) STORE{MEMORY[ty]}({self.expr(st.addr, tmps)}, "
                                    f"{self.expr(st.data, tmps)});")
                    elif isinstance(st, pyvex.stmt.Exit):
                        if st.jumpkind.startswith("Ijk_Sig"):
                            # A trap the guest raises (division by zero, ud2): the program's atlas_trap decides.
                            kind = TRAPS.get(st.jumpkind, 0)
                            body.append(f"      if ({self.expr(st.guard, tmps)}) {{ atlas_trap(s, {a:#x}ULL, {kind}); return; }}")
                            continue
                        if st.jumpkind == "Ijk_EmWarn":
                            # VEX's warning that the x87 control word asks for what it does not model (a precision
                            # other than double): the processor goes on, and so does the translation.
                            continue
                        if st.jumpkind == "Ijk_NoDecode":
                            # Thumb: an instruction not allowed inside an IT block (a conditional branch...) comes
                            # with this exit, taken only when ITSTATE says it is in one: undefined, so a trap.
                            at = st.dst.value & self.mask
                            body.append(f"      if ({self.expr(st.guard, tmps)}) {{ atlas_trap(s, {at:#x}ULL, 3); return; }}")
                            continue
                        if st.jumpkind == "Ijk_Ret":
                            # A conditional return whose target VEX does not give here: taken as the expected one.
                            body.append(f"      if ({self.expr(st.guard, tmps)}) {{ s->returned = ATLAS_RETURNED_ANY; return; }}")
                            continue
                        if st.jumpkind == "Ijk_Call":
                            # A conditional call (ARM's bleq): back to the instruction after it.
                            after = (last_mark[0] + last_mark[1]) & self.mask
                            todo.append(after)
                            body.append(f"      if ({self.expr(st.guard, tmps)}) {{ {self.call(f'{st.dst.value & self.mask:#x}ULL', after)} }}")
                            continue
                        if st.jumpkind != "Ijk_Boring":
                            raise Unsupported(f"conditional exit {st.jumpkind}")
                        target = st.dst.value & self.mask
                        todo.append(target)
                        inside = self.address <= target < self.end
                        jump = f"pc = {target:#x}ULL; continue;" if inside else f"atlas_call(s, {target:#x}ULL); return;"
                        body.append(f"      if ({self.expr(st.guard, tmps)}) {{ {jump} }}")
                    else:
                        raise Unsupported(f"statement {type(st).__name__}")
                nxt = irsb.next
                constant = nxt.con.value & self.mask if isinstance(nxt, pyvex.expr.Const) else None
                masked = "" if self.mask == ~0 else " & ~1ULL"
                if irsb.jumpkind == "Ijk_Ret":
                    # The return's real target, for the call site to check (a return may skip a level).
                    target = f"{constant:#x}ULL" if constant is not None else f"(uint64_t)({self.expr(nxt, tmps)}){masked}"
                    body.append(f"      s->returned = {target}; return;")
                elif irsb.jumpkind == "Ijk_Call":
                    target = f"{constant:#x}ULL" if constant is not None else f"({self.expr(nxt, tmps)}){masked}"
                    after = a + irsb.size
                    # The callee returns to the instruction after the call (the return address the call pushed or the
                    # link register it set is part of the state the translation already wrote).
                    # ATLAS_CALL (atlas_lift.h): atlas_call, or what a linked program puts there (setjmp has to run in
                    # this function's frame, so a link can expand it here).
                    body.append(f"      {self.call(target, after)}")
                    todo.append(after)
                elif irsb.jumpkind == "Ijk_Boring":
                    if constant is not None and self.address <= constant < self.end:
                        todo.append(constant)
                        body.append(f"      pc = {constant:#x}ULL; continue;")
                    elif constant is not None:
                        body.append(f"      atlas_call(s, {constant:#x}ULL); return;  /* tail jump */")
                    else:
                        # A jump through a register: a switch table inside the function, or a tail call elsewhere.
                        body.append(f"      pc = ({self.expr(nxt, tmps)}){masked}; continue;")
                elif irsb.jumpkind == "Ijk_Sys_syscall" and constant is not None:
                    # A system call (svc, syscall): the program's atlas_syscall serves it from the guest registers.
                    todo.append(constant)
                    body.append(f"      atlas_syscall(s); pc = {constant:#x}ULL; continue;")
                elif irsb.jumpkind == "Ijk_NoDecode":
                    stop = a + irsb.size
                    target = self.thumb_branch(stop) if self.thumb else None
                    if target is not None:
                        # VEX's Thumb decoder refuses some far backward B.W (encoding T4): decoded here.
                        if self.address <= target < self.end:
                            todo.append(target)
                            body.append(f"      pc = {target:#x}ULL; continue;")
                        else:
                            body.append(f"      atlas_call(s, {target:#x}ULL); return;  /* tail jump */")
                    else:
                        body.append(f"      atlas_trap(s, {stop:#x}ULL, 3); return;")
                elif irsb.jumpkind.startswith("Ijk_Sig"):
                    body.append(f"      atlas_trap(s, {a:#x}ULL, {TRAPS.get(irsb.jumpkind, 0)}); return;")
                else:
                    raise Unsupported(f"jump kind {irsb.jumpkind}")
                body.append("    }")
                out.append("\n".join(body))
            except Unsupported:
                # A block found only by the linear sweep that is not real code (data decoded as x87, say):
                # skipped, with the targets it added.
                if a not in optional:
                    raise
                del todo[mark:]
        name = f"fn_{self.address:x}"
        return (f"void {name}(atlas_state *s) {{\n  uint64_t pc = {self.address:#x}ULL;\n  for (;;) {{\n"
                f"    switch (pc) {{\n" + "\n".join(out) + "\n    default: atlas_call(s, pc); return;\n    }\n  }\n}\n")


def load(binary, base=0):
    """The binary as angr loads it (at 0 if position-independent, as the graph has it), every target of an
    indirect jump its CFG resolves (switch tables), and the functions its CFG finds in Thumb state (32-bit ARM: odd
    addresses in angr; the graph keeps the even address only, so the state is taken from here)."""
    import angr
    import logging

    logging.getLogger("angr").setLevel(logging.ERROR)
    proj = angr.Project(binary, auto_load_libs=False, main_opts={"base_addr": base})
    cfg = proj.analyses.CFGFast(resolve_indirect_jumps=True, normalize=True)
    out = set()
    for jump in cfg.indirect_jumps.values():
        out.update(jump.resolved_targets or ())
    thumb = {a & ~1 for a in cfg.functions if a & 1} if proj.arch.name.startswith("ARM") else set()
    return proj.loader.memory, out, thumb


def unlisted_pe_functions(binary, functions):
    """A Windows x64 image lists every function with unwind data in its exception directory (.pdata): those the
    request does not have (an engine can miss one, as Ghidra did a function after a call that does not return) are
    translated too, so a linked program has them (marked "extra" in the output). Not a PE, or none: nothing."""
    import pefile

    try:
        pe = pefile.PE(binary, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
    except pefile.PEFormatError:
        return []
    base = pe.OPTIONAL_HEADER.ImageBase
    have = {f["address"] for f in functions}
    out = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []):
        start, end = base + entry.struct.BeginAddress, base + entry.struct.EndAddress
        if start not in have and end > start:
            code = pe.get_data(entry.struct.BeginAddress, end - start).hex()
            out.append({"address": start, "code": code, "extra": True})
    return out


def main():
    request = json.load(open(sys.argv[1]))
    arch = archinfo.arch_from_id(request["arch"], request.get("endness", "any"))
    # base: where a position-independent image is placed (the graph has it at 0). A linked program maps the image
    # there, since Linux keeps the first 64 KiB, where a small program's code lies; translations use those addresses.
    base = int(request.get("base", 0))
    memory, targets, thumbs = load(request["binary"], base) if request.get("binary") else (None, set(), set())
    targets = sorted(targets)
    functions = list(request["functions"]) + (unlisted_pe_functions(request["binary"], request["functions"])
                                              if request.get("binary") else [])
    for f in functions:
        try:
            thumb = bool(f.get("thumb")) or f["address"] + base in thumbs
            try:
                c = Function(arch, f["address"] + base, f["code"], targets, thumb, memory).translate()
            except Unsupported as reason:
                # ARM: the CFG's Thumb or ARM guess can be wrong (interworking stubs, bx pc): the other state is
                # tried when the guessed one does not decode.
                if not (arch.name.startswith("ARM") and str(reason).startswith("undecodable")):
                    raise
                try:
                    c = Function(arch, f["address"] + base, f["code"], targets, not thumb, memory).translate()
                except Unsupported:
                    raise reason from None  # the guessed state's reason is the one to report
            extra = {"extra": True} if f.get("extra") else {}
            print(json.dumps({"address": hex(f["address"]), "c": c, **extra}), flush=True)  # the graph's address
        except Unsupported as reason:
            print(json.dumps({"address": hex(f["address"]), "unsupported": str(reason)}), flush=True)
        except Exception as error:  # a translator bug is reported per function, not a crash of the run
            print(json.dumps({"address": hex(f["address"]), "unsupported": f"translator error: {error}"[:300]}),
                  flush=True)


if __name__ == "__main__":
    main()
