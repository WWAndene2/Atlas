/* Runtime of Atlas's static recompilation (lift.py): the guest state, memory access and the helpers VEX calls.
 * A translation includes this header after defining ATLAS_BIG_ENDIAN for big-endian guests. The program that links
 * the translations provides atlas_call (the dispatch from a guest address to its translation) and the memory map
 * (ATLAS_HOST, guest address to host pointer; flat by default). */
#ifndef ATLAS_LIFT_H
#define ATLAS_LIFT_H
#include <stdint.h>
#include <string.h>

typedef struct atlas_state {
  /* Guest registers at their VEX offsets; 4 KiB covers every guest VEX describes. */
  uint8_t r[4096] __attribute__((aligned(16)));
  /* Flat guest memory by default: guest address a lives at mem + a. */
  uint8_t *mem;
  /* Where the last return went (lift.py): a call site sets it to the address it expects, a return writes its real
   * target, and a call site that finds another address unwinds (a return that skips a level). ATLAS_RETURNED_ANY:
   * a return whose target is not known (a host call, a longjmp's landing), taken as the expected one. */
  uint64_t returned;
  /* The immediate of the system call instruction being served (svc #n): where a kernel takes the call's number
   * from the instruction rather than a register (Horizon); 0 when the instruction has none (x86's syscall). */
  uint32_t svc;
} atlas_state;
#define ATLAS_RETURNED_ANY (~0ULL)

void atlas_call(atlas_state *s, uint64_t target);
/* A trap the guest raised (division by zero, ud2, breakpoint): the program decides what it does. */
void atlas_trap(atlas_state *s, uint64_t at, int kind);
/* A system call the guest makes (svc, syscall), served by the program (the platform's services). */
void atlas_syscall(atlas_state *s);

#define REG(T, off) (*(T *)(s->r + (off)))
/* A call from a translation: the program may expand it in the calling function itself (setjmp, see link.py). */
#ifndef ATLAS_CALL
#define ATLAS_CALL(target) atlas_call(s, (target))
#endif
#ifndef ATLAS_HOST
#ifdef ATLAS_IDENTITY
/* A linked program on a host of the same architecture: the guest's memory is mapped at its own addresses. */
#define ATLAS_HOST(a) ((uint8_t *)(uintptr_t)(a))
#else
#define ATLAS_HOST(a) (s->mem + (uint64_t)(a))
#endif
#endif

#ifdef ATLAS_BIG_ENDIAN
#define SWAP8(v) (v)
#define SWAP16(v) __builtin_bswap16(v)
#define SWAP32(v) __builtin_bswap32(v)
#define SWAP64(v) __builtin_bswap64(v)
#else
#define SWAP8(v) (v)
#define SWAP16(v) (v)
#define SWAP32(v) (v)
#define SWAP64(v) (v)
#endif
/* ATLAS_MEM_LIMIT (checks only): guest memory past it reads as zero and ignores writes, as the original's
 * side of a behaviour check sees unmapped memory, instead of crashing the run. */
#ifdef ATLAS_MEM_LIMIT
#define ATLAS_OUTSIDE(a, n) ((uint64_t)(a) > (uint64_t)ATLAS_MEM_LIMIT - (n))
#else
#define ATLAS_OUTSIDE(a, n) 0
#endif
#ifdef ATLAS_PAGED
/* Paged guest memory (checks with captured inputs, whose addresses span the 64-bit space): pages of 4 KiB made on
 * first use by atlas_page. Accesses are out of line (inlined, a large translation took over 30 minutes to compile),
 * and byte by byte only when they cross two pages. */
uint8_t *atlas_page(atlas_state *s, uint64_t a);
#define ATLAS_LOAD(N)                                                                        \
  static __attribute__((noinline)) uint##N##_t atlas_load##N(atlas_state *s, uint64_t a) {   \
    uint8_t b[N / 8];                                                                        \
    uint##N##_t v;                                                                           \
    if ((a & 0xfff) <= 4096 - N / 8) memcpy(b, atlas_page(s, a) + (a & 0xfff), N / 8);      \
    else for (unsigned i = 0; i < N / 8; i++) b[i] = atlas_page(s, a + i)[(a + i) & 0xfff]; \
    memcpy(&v, b, sizeof v);                                                                 \
    return SWAP##N(v);                                                                       \
  }                                                                                          \
  static __attribute__((noinline)) void atlas_store##N(atlas_state *s, uint64_t a, uint##N##_t v) { \
    uint8_t b[N / 8];                                                                        \
    v = SWAP##N(v);                                                                          \
    memcpy(b, &v, sizeof v);                                                                 \
    if ((a & 0xfff) <= 4096 - N / 8) memcpy(atlas_page(s, a) + (a & 0xfff), b, N / 8);      \
    else for (unsigned i = 0; i < N / 8; i++) atlas_page(s, a + i)[(a + i) & 0xfff] = b[i]; \
  }
#else
/* ATLAS_DEVICE_LOW and ATLAS_DEVICE_HIGH (a machine's hardware registers, console/devices.inc): accesses in
 * [low, high) go to the program's devices instead of memory, values as the guest sees them (byte order applied). One
 * comparison per access, and none at all when the machine has no such window. */
#ifdef ATLAS_DEVICE_LOW
uint64_t atlas_device_load(atlas_state *s, uint64_t a, unsigned size);
void atlas_device_store(atlas_state *s, uint64_t a, unsigned size, uint64_t v);
#define ATLAS_DEVICE(a) ((uint64_t)(a) - (uint64_t)ATLAS_DEVICE_LOW < (uint64_t)ATLAS_DEVICE_HIGH - ATLAS_DEVICE_LOW)
#else
#define ATLAS_DEVICE(a) 0
#define atlas_device_load(s, a, n) 0
#define atlas_device_store(s, a, n, v) ((void)0)
#endif
#define ATLAS_LOAD(N)                                                         \
  static inline uint##N##_t atlas_load##N(atlas_state *s, uint64_t a) {       \
    uint##N##_t v;                                                            \
    if (ATLAS_OUTSIDE(a, sizeof v)) return 0;                                 \
    if (ATLAS_DEVICE(a)) return (uint##N##_t)atlas_device_load(s, a, N / 8);  \
    memcpy(&v, ATLAS_HOST(a), sizeof v);                                      \
    return SWAP##N(v);                                                        \
  }                                                                           \
  static inline void atlas_store##N(atlas_state *s, uint64_t a, uint##N##_t v) { \
    if (ATLAS_OUTSIDE(a, sizeof v)) return;                                   \
    if (ATLAS_DEVICE(a)) {                                                    \
      atlas_device_store(s, a, N / 8, v);                                     \
      return;                                                                 \
    }                                                                         \
    v = SWAP##N(v);                                                           \
    memcpy(ATLAS_HOST(a), &v, sizeof v);                                      \
  }
#endif
ATLAS_LOAD(8)
ATLAS_LOAD(16)
ATLAS_LOAD(32)
ATLAS_LOAD(64)
#define LOAD8(a) atlas_load8(s, (a))
#define LOAD16(a) atlas_load16(s, (a))
#define LOAD32(a) atlas_load32(s, (a))
#define LOAD64(a) atlas_load64(s, (a))
#define STORE8(a, v) atlas_store8(s, (a), (uint8_t)(v))
#define STORE16(a, v) atlas_store16(s, (a), (uint16_t)(v))
#define STORE32(a, v) atlas_store32(s, (a), (uint32_t)(v))
#define STORE64(a, v) atlas_store64(s, (a), (uint64_t)(v))

/* ---- Floating point and 128-bit vectors (SSE's low-lane operations), under VEX's operation names. */
#include <math.h>
typedef unsigned __int128 v128;
static inline double atlas_reinterp_i64_f64(uint64_t v) { double d; memcpy(&d, &v, 8); return d; }
static inline uint64_t atlas_reinterp_f64_i64(double d) { uint64_t v; memcpy(&v, &d, 8); return v; }
static inline float atlas_reinterp_i32_f32(uint32_t v) { float f; memcpy(&f, &v, 4); return f; }
static inline uint32_t atlas_reinterp_f32_i32(float f) { uint32_t v; memcpy(&v, &f, 4); return v; }
#define LOADF64(a) atlas_reinterp_i64_f64(LOAD64(a))
#define LOADF32(a) atlas_reinterp_i32_f32(LOAD32(a))
#define STOREF64(a, v) STORE64((a), atlas_reinterp_f64_i64(v))
#define STOREF32(a, v) STORE32((a), atlas_reinterp_f32_i32(v))
#ifdef ATLAS_BIG_ENDIAN
#define LOADV128(a) (((v128)LOAD64(a) << 64) | LOAD64((a) + 8))
#define STOREV128(a, v) (STORE64((a), (uint64_t)((v) >> 64)), STORE64((a) + 8, (uint64_t)(v)))
#else
#define LOADV128(a) (((v128)LOAD64((a) + 8) << 64) | LOAD64(a))
#define STOREV128(a, v) (STORE64((a), (uint64_t)(v)), STORE64((a) + 8, (uint64_t)((v) >> 64)))
#endif
static inline v128 atlas_and_v128(v128 a, v128 b) { return a & b; }
static inline v128 atlas_or_v128(v128 a, v128 b) { return a | b; }
static inline v128 atlas_xor_v128(v128 a, v128 b) { return a ^ b; }
static inline v128 atlas_not_v128(v128 a) { return ~a; }
static inline v128 atlas_64uto_v128(uint64_t a) { return a; }
static inline v128 atlas_32uto_v128(uint32_t a) { return a; }
static inline uint64_t atlas_v128to64(v128 a) { return (uint64_t)a; }
static inline uint32_t atlas_v128to32(v128 a) { return (uint32_t)a; }
static inline uint64_t atlas_v128hito64(v128 a) { return (uint64_t)(a >> 64); }
static inline v128 atlas_64hlto_v128(uint64_t h, uint64_t l) { return ((v128)h << 64) | l; }
static inline v128 atlas_setv128lo64(v128 a, uint64_t l) { return (a & ~(v128)~0ULL) | l; }
static inline v128 atlas_setv128lo32(v128 a, uint32_t l) { return (a & ~(v128)0xffffffffULL) | l; }
/* Interleaves (VEX: the left operand's lanes go high): LO64x2 = [L.lo64 | R.lo64], LO32x4 = L1 R1 L0 R0. */
static inline v128 atlas_interleavelo64x2(v128 l, v128 r) { return ((v128)(uint64_t)l << 64) | (uint64_t)r; }
static inline v128 atlas_interleavehi64x2(v128 l, v128 r) { return (l & ((v128)~0ULL << 64)) | (uint64_t)(r >> 64); }
static inline v128 atlas_zerohi64ofv128(v128 a) { return (uint64_t)a; }
/* rev64 on a vector: the bytes of each 64-bit lane in reverse order. */
static inline v128 atlas_reverse8sin64x2(v128 a) {
  return ((v128)__builtin_bswap64((uint64_t)(a >> 64)) << 64) | __builtin_bswap64((uint64_t)a);
}
static inline v128 atlas_lane32(v128 v, int i) { return (uint32_t)(v >> (32 * i)); }
static inline v128 atlas_interleavelo32x4(v128 l, v128 r) {
  return atlas_lane32(r, 0) | atlas_lane32(l, 0) << 32 | atlas_lane32(r, 1) << 64 | atlas_lane32(l, 1) << 96;
}
static inline v128 atlas_interleavehi32x4(v128 l, v128 r) {
  return atlas_lane32(r, 2) | atlas_lane32(l, 2) << 32 | atlas_lane32(r, 3) << 64 | atlas_lane32(l, 3) << 96;
}
static inline v128 atlas_shln64x2(v128 v, uint8_t n) {
  if (n > 63) return 0;
  return ((v128)((uint64_t)(v >> 64) << n) << 64) | (uint64_t)((uint64_t)v << n);
}
static inline v128 atlas_shrn64x2(v128 v, uint8_t n) {
  if (n > 63) return 0;
  return ((v128)((uint64_t)(v >> 64) >> n) << 64) | (uint64_t)((uint64_t)v >> n);
}
/* Per-lane integer vector operations (Add64x2...): the vector seen as lanes of W bits. */
#define ATLAS_LANES(NAME, W, EXPR)                                                    \
  static inline v128 NAME(v128 a, v128 b) {                                           \
    uint##W##_t x[128 / W], y[128 / W], r[128 / W];                                   \
    memcpy(x, &a, 16); memcpy(y, &b, 16);                                             \
    for (unsigned i = 0; i < 128 / W; i++) r[i] = (uint##W##_t)(EXPR);               \
    v128 out; memcpy(&out, r, 16); return out;                                        \
  }
ATLAS_LANES(atlas_add8x16, 8, x[i] + y[i])
ATLAS_LANES(atlas_add16x8, 16, x[i] + y[i])
ATLAS_LANES(atlas_add32x4, 32, x[i] + y[i])
ATLAS_LANES(atlas_add64x2, 64, x[i] + y[i])
ATLAS_LANES(atlas_sub8x16, 8, x[i] - y[i])
ATLAS_LANES(atlas_sub16x8, 16, x[i] - y[i])
ATLAS_LANES(atlas_sub32x4, 32, x[i] - y[i])
ATLAS_LANES(atlas_sub64x2, 64, x[i] - y[i])
ATLAS_LANES(atlas_cmpeq8x16, 8, x[i] == y[i] ? 0xff : 0)
ATLAS_LANES(atlas_cmpeq16x8, 16, x[i] == y[i] ? 0xffff : 0)
ATLAS_LANES(atlas_cmpeq32x4, 32, x[i] == y[i] ? 0xffffffffu : 0)
ATLAS_LANES(atlas_cmpeq64x2, 64, x[i] == y[i] ? ~0ULL : 0)
static inline double atlas_lo_f64(v128 a) { return atlas_reinterp_i64_f64((uint64_t)a); }
static inline v128 atlas_with_lo_f64(v128 a, double d) { return atlas_setv128lo64(a, atlas_reinterp_f64_i64(d)); }
static inline v128 atlas_add64f0x2(v128 a, v128 b) { return atlas_with_lo_f64(a, atlas_lo_f64(a) + atlas_lo_f64(b)); }
static inline v128 atlas_sub64f0x2(v128 a, v128 b) { return atlas_with_lo_f64(a, atlas_lo_f64(a) - atlas_lo_f64(b)); }
static inline v128 atlas_mul64f0x2(v128 a, v128 b) { return atlas_with_lo_f64(a, atlas_lo_f64(a) * atlas_lo_f64(b)); }
static inline v128 atlas_div64f0x2(v128 a, v128 b) { return atlas_with_lo_f64(a, atlas_lo_f64(a) / atlas_lo_f64(b)); }
static inline v128 atlas_sqrt64f0x2(v128 a) { return atlas_with_lo_f64(a, sqrt(atlas_lo_f64(a))); }
static inline v128 atlas_cmp_lo(v128 a, int r) { return atlas_setv128lo64(a, r ? ~0ULL : 0); }
static inline v128 atlas_cmple64f0x2(v128 a, v128 b) { return atlas_cmp_lo(a, atlas_lo_f64(a) <= atlas_lo_f64(b)); }
static inline v128 atlas_cmplt64f0x2(v128 a, v128 b) { return atlas_cmp_lo(a, atlas_lo_f64(a) < atlas_lo_f64(b)); }
static inline v128 atlas_cmpeq64f0x2(v128 a, v128 b) { return atlas_cmp_lo(a, atlas_lo_f64(a) == atlas_lo_f64(b)); }
static inline v128 atlas_cmpun64f0x2(v128 a, v128 b) { return atlas_cmp_lo(a, isunordered(atlas_lo_f64(a), atlas_lo_f64(b))); }
/* IRCmpF64Result: unordered 0x45, less 0x01, equal 0x40, greater 0x00. */
static inline uint32_t atlas_cmpf64(double a, double b) {
  return isunordered(a, b) ? 0x45 : a < b ? 0x01 : a == b ? 0x40 : 0x00;
}
/* VEX's rounding modes: 0 nearest (even), 1 toward -inf, 2 toward +inf, 3 toward zero. */
static inline double atlas_round(uint32_t rm, double d) {
  switch (rm & 3) { case 0: return nearbyint(d); case 1: return floor(d); case 2: return ceil(d); default: return trunc(d); }
}
static inline uint64_t atlas_f64toi64s(uint32_t rm, double d) {
  double r = atlas_round(rm, d);
  return (isnan(r) || r >= 9223372036854775808.0 || r < -9223372036854775808.0) ? 0x8000000000000000ULL : (uint64_t)(int64_t)r;
}
static inline uint32_t atlas_f64toi32s(uint32_t rm, double d) {
  double r = atlas_round(rm, d);
  return (isnan(r) || r >= 2147483648.0 || r < -2147483648.0) ? 0x80000000U : (uint32_t)(int32_t)r;
}
static inline double atlas_i64stof64(uint32_t rm, uint64_t v) { (void)rm; return (double)(int64_t)v; }
static inline double atlas_i32stof64(uint32_t v) { return (double)(int32_t)v; }
static inline double atlas_f32tof64(float f) { return f; }
static inline float atlas_f64tof32(uint32_t rm, double d) { (void)rm; return (float)d; }
static inline double atlas_addf64(uint32_t rm, double a, double b) { (void)rm; return a + b; }
static inline double atlas_subf64(uint32_t rm, double a, double b) { (void)rm; return a - b; }
static inline double atlas_mulf64(uint32_t rm, double a, double b) { (void)rm; return a * b; }
static inline double atlas_divf64(uint32_t rm, double a, double b) { (void)rm; return a / b; }
/* x87 fprem: the partial remainder (complete in one step here: C2 clear) and its condition bits as the FPU status
 * word holds them (C0 bit 8, C1 bit 9, C2 bit 10, C3 bit 14) from the quotient's low three bits. */
static inline double atlas_premf64(uint32_t rm, double a, double b) { (void)rm; return fmod(a, b); }
static inline uint32_t atlas_premc3210f64(uint32_t rm, double a, double b) {
  (void)rm;
  if (isnan(a) || isnan(b) || isinf(a) || b == 0) return 0;
  uint64_t q = (uint64_t)(int64_t)trunc(fabs(a / b));
  return (uint32_t)(((q >> 2) & 1) << 8 | (q & 1) << 9 | ((q >> 1) & 1) << 14);
}
static inline double atlas_sqrtf64(uint32_t rm, double a) { (void)rm; return sqrt(a); }
/* AArch64's fused multiply-add (fmadd, fmsub): a * b + c and a * b - c, rounded once. */
static inline double atlas_maddf64(uint32_t rm, double a, double b, double c) { (void)rm; return fma(a, b, c); }
static inline double atlas_msubf64(uint32_t rm, double a, double b, double c) { (void)rm; return fma(a, b, -c); }
/* fprem1: the IEEE remainder (quotient rounded to nearest), its condition bits as fprem's from that quotient. */
static inline double atlas_prem1f64(uint32_t rm, double a, double b) { (void)rm; return remainder(a, b); }
static inline uint32_t atlas_prem1c3210f64(uint32_t rm, double a, double b) {
  (void)rm;
  if (isnan(a) || isnan(b) || isinf(a) || b == 0) return 0;
  uint64_t q = (uint64_t)(int64_t)fabs(nearbyint(a / b));
  return (uint32_t)(((q >> 2) & 1) << 8 | (q & 1) << 9 | ((q >> 1) & 1) << 14);
}
/* f2xm1: 2^a - 1. */
static inline double atlas_2xm1f64(uint32_t rm, double a) { (void)rm; return expm1(a * M_LN2); }
/* x87 fpatan: arctan(a / b), in the quadrant of (b, a). fscale: a * 2^b, b rounded toward zero. */
static inline double atlas_atanf64(uint32_t rm, double a, double b) { (void)rm; return atan2(a, b); }
/* fyl2x: a * log2(b); fyl2xp1: a * log2(b + 1). fsin, fcos. frndint is atlas_round, in the rounding mode given. */
static inline double atlas_yl2xf64(uint32_t rm, double a, double b) { (void)rm; return a * log2(b); }
static inline double atlas_yl2xp1f64(uint32_t rm, double a, double b) { (void)rm; return a * log1p(b) / M_LN2; }
static inline double atlas_sinf64(uint32_t rm, double a) { (void)rm; return sin(a); }
static inline double atlas_cosf64(uint32_t rm, double a) { (void)rm; return cos(a); }
static inline double atlas_scalef64(uint32_t rm, double a, double b) {
  (void)rm;
  double n = trunc(b);
  return isnan(n) ? n : ldexp(a, n > 1e5 ? 100000 : n < -1e5 ? -100000 : (int)n);
}

/* ---- x86-64 condition codes, from VEX's lazy flags thunk (cc_op, dep1, dep2, ndep), as in VEX's
 * guest_amd64_helpers.c: operation families in blocks of four sizes (B, W, L, Q). */
enum { A_C = 1 << 0, A_P = 1 << 2, A_A = 1 << 4, A_Z = 1 << 6, A_S = 1 << 7, A_O = 1 << 11 };

static inline uint64_t atlas_parity(uint64_t r) { return (__builtin_popcountll(r & 0xff) & 1) ? 0 : A_P; }

static inline uint64_t amd64g_calculate_rflags_all(uint64_t op, uint64_t d1, uint64_t d2, uint64_t nd) {
  if (op == 0) return d1 & (A_C | A_P | A_A | A_Z | A_S | A_O); /* COPY */
  if (op < 1 || op > 52) return 0;
  unsigned family = (unsigned)((op - 1) / 4), size = (unsigned)((op - 1) % 4);
  unsigned bits = 8u << size;
  uint64_t mask = bits == 64 ? ~0ULL : ((1ULL << bits) - 1), sign = 1ULL << (bits - 1);
  uint64_t res = 0, c = 0, o = 0, a = 0;
  switch (family) {
    case 0: /* ADD */
      res = (d1 + d2) & mask; c = res < (d1 & mask); a = (res ^ d1 ^ d2) & 0x10;
      o = ((d1 ^ d2 ^ sign) & (d1 ^ res) & sign) ? A_O : 0; break;
    case 1: /* SUB */
      res = (d1 - d2) & mask; c = (d1 & mask) < (d2 & mask); a = (res ^ d1 ^ d2) & 0x10;
      o = ((d1 ^ d2) & (d1 ^ res) & sign) ? A_O : 0; break;
    case 2: { /* ADC: dep2 = argR ^ oldC, ndep = oldC */
      uint64_t oc = nd & A_C, r2 = d2 ^ oc;
      res = (d1 + r2 + oc) & mask; c = oc ? res <= (d1 & mask) : res < (d1 & mask);
      a = (res ^ d1 ^ r2) & 0x10; o = ((d1 ^ r2 ^ sign) & (d1 ^ res) & sign) ? A_O : 0; break; }
    case 3: { /* SBB */
      uint64_t oc = nd & A_C, r2 = d2 ^ oc;
      res = (d1 - r2 - oc) & mask; c = oc ? (d1 & mask) <= (r2 & mask) : (d1 & mask) < (r2 & mask);
      a = (res ^ d1 ^ r2) & 0x10; o = ((d1 ^ r2) & (d1 ^ res) & sign) ? A_O : 0; break; }
    case 4: res = d1 & mask; break; /* LOGIC */
    case 5: /* INC: ndep = oldC */
      res = d1 & mask; c = nd & A_C; a = (res ^ (res - 1) ^ 1) & 0x10; o = res == sign ? A_O : 0; break;
    case 6: /* DEC */
      res = d1 & mask; c = nd & A_C; a = (res ^ (res + 1) ^ 1) & 0x10; o = res == sign - 1 ? A_O : 0; break;
    case 7: /* SHL: dep1 = result, dep2 = value shifted one less */
      res = d1 & mask; c = (d2 >> (bits - 1)) & 1; o = ((res ^ d2) & sign) ? A_O : 0; break;
    case 8: /* SHR/SAR */
      res = d1 & mask; c = d2 & 1; o = ((res ^ d2) & sign) ? A_O : 0; break;
    case 9: /* ROL: ndep = old flags */
      return (nd & ~(uint64_t)(A_C | A_O)) | (d1 & 1) | ((((d1 >> (bits - 1)) ^ d1) & 1) ? A_O : 0);
    case 10: /* ROR */
      return (nd & ~(uint64_t)(A_C | A_O)) | ((d1 >> (bits - 1)) & 1) |
             ((((d1 >> (bits - 1)) ^ (d1 >> (bits - 2))) & 1) ? A_O : 0);
    case 11: { /* UMUL */
      unsigned __int128 p = (unsigned __int128)(d1 & mask) * (d2 & mask);
      res = (uint64_t)p & mask; c = bits == 64 ? (uint64_t)(p >> 64) != 0 : ((uint64_t)p >> bits) != 0;
      o = c ? A_O : 0; break; }
    case 12: { /* SMUL */
      __int128 x = bits == 64 ? (int64_t)d1 : (int64_t)((d1 & mask) ^ sign) - (int64_t)sign;
      __int128 y = bits == 64 ? (int64_t)d2 : (int64_t)((d2 & mask) ^ sign) - (int64_t)sign;
      __int128 p = x * y; res = (uint64_t)p & mask;
      __int128 back = bits == 64 ? (int64_t)res : (int64_t)((res ^ sign)) - (int64_t)sign;
      c = p != back; o = c ? A_O : 0; break; }
    default: return 0;
  }
  return (c ? A_C : 0) | atlas_parity(res) | a | (res == 0 ? A_Z : 0) | ((res & sign) ? A_S : 0) | o;
}

static inline uint64_t amd64g_calculate_rflags_c(uint64_t op, uint64_t d1, uint64_t d2, uint64_t nd) {
  return amd64g_calculate_rflags_all(op, d1, d2, nd) & A_C;
}

static inline uint64_t amd64g_calculate_condition(uint64_t cond, uint64_t op, uint64_t d1, uint64_t d2, uint64_t nd) {
  uint64_t f = amd64g_calculate_rflags_all(op, d1, d2, nd);
  int of = !!(f & A_O), sf = !!(f & A_S), zf = !!(f & A_Z), cf = !!(f & A_C), pf = !!(f & A_P), r;
  switch (cond >> 1) {
    case 0: r = of; break;              /* O */
    case 1: r = cf; break;              /* B */
    case 2: r = zf; break;              /* Z */
    case 3: r = cf | zf; break;         /* BE */
    case 4: r = sf; break;              /* S */
    case 5: r = pf; break;              /* P */
    case 6: r = sf ^ of; break;         /* L */
    default: r = (sf ^ of) | zf; break; /* LE */
  }
  return (uint64_t)(r ^ (int)(cond & 1));
}
/* ---- x86-64 helpers with side effects (lift.py's DIRTY), on the guest state at VEX's AMD64 offsets. */
/* fninit: the x87 stack empty and its top at 0, round to nearest, condition codes clear (VEX's
 * amd64g_dirtyhelper_FINIT). */
static inline void amd64g_dirtyhelper_FINIT(uint8_t *r) {
  memset(r + 2400, 0, 4);  /* FTOP */
  memset(r + 2408, 0, 64); /* the eight registers */
  memset(r + 2472, 0, 8);  /* their tags: empty */
  memset(r + 2480, 0, 8);  /* FPROUND: nearest */
  memset(r + 2488, 0, 8);  /* FC3210 */
}
/* x87 control word (VEX's guest_amd64_helpers.c): fnstcw gives the rounding mode with every exception masked and
 * extended precision; fldcw keeps only the rounding mode (the emulation-warning half, the high word, is 0: what
 * VEX does not model is left as the processor has it). */
static inline uint64_t amd64g_create_fpucw(uint64_t fpround) { return ((fpround & 3) << 10) | 0x037F; }
static inline uint64_t amd64g_check_fldcw(uint64_t fpucw) { return (fpucw >> 10) & 3; }
/* fxam: the class of st(0) in C3, C2, C0 (FSW bits 14, 10, 8), its sign in C1 (bit 9); tag 0 is an empty register. */
static inline uint64_t amd64g_calculate_FXAM(uint64_t tag, uint64_t bits) {
  uint64_t sign = ((bits >> 63) & 1) << 9, exp = (bits >> 52) & 0x7ff, mant = bits & 0xfffffffffffffULL;
  enum { C0 = 1 << 8, C2 = 1 << 10, C3 = 1 << 14 };
  if (tag == 0) return C3 | C0 | sign;                 /* empty */
  if (exp == 0) return (mant ? C3 | C2 : C3) | sign;   /* denormal, zero */
  if (exp == 0x7ff) return (mant ? C0 : C2 | C0) | sign; /* NaN, infinity */
  return C2 | sign;                                    /* normal */
}
/* x87's 80-bit loads and stores (fld and fstp of a ten-byte operand): VEX holds x87 values as doubles, so the
 * value is converted, rounded to nearest, as VEX's helpers do. Through the host's long double, which is the same
 * 80-bit format on an x86 host; a host without it has no definition, and a translation using them does not build. */
#if defined(__LDBL_MANT_DIG__) && __LDBL_MANT_DIG__ == 64
static inline uint64_t amd64g_dirtyhelper_loadF80le(atlas_state *s, uint64_t a) {
  long double x = 0;
  for (int i = 0; i < 10; i++) ((uint8_t *)&x)[i] = LOAD8(a + i);
  return atlas_reinterp_f64_i64((double)x);
}
static inline void amd64g_dirtyhelper_storeF80le(atlas_state *s, uint64_t a, uint64_t bits) {
  long double x = atlas_reinterp_i64_f64(bits);
  for (int i = 0; i < 10; i++) STORE8(a + i, ((uint8_t *)&x)[i]);
}
#endif
/* ---- ARM condition flags, from VEX's thunk (as guest_arm_helpers.c): cc_op COPY 0 (dep1 holds NZCV in bits 31-28),
 * ADD 1, SUB 2, ADC 3 and SBB 4 (ndep: old C), LOGIC 5 (dep1 result, dep2 shifter carry, ndep old V), MUL 6 and
 * MULL 7 (ndep: old C in bit 1, old V in bit 0). Results: NZCV in bits 31-28. */
static inline uint32_t armg_calculate_flags_nzcv(uint32_t op, uint32_t d1, uint32_t d2, uint32_t nd) {
  uint32_t n = 0, z = 0, c = 0, v = 0, r;
  switch (op) {
    case 0: return d1 & 0xf0000000u;
    case 1: r = d1 + d2; n = r >> 31; z = r == 0; c = r < d1; v = ((r ^ d1) & (r ^ d2)) >> 31; break;
    case 2: r = d1 - d2; n = r >> 31; z = r == 0; c = d1 >= d2; v = ((d1 ^ d2) & (d1 ^ r)) >> 31; break;
    case 3: r = d1 + d2 + nd; n = r >> 31; z = r == 0; c = nd ? r <= d1 : r < d1; v = ((r ^ d1) & (r ^ d2)) >> 31; break;
    case 4: r = d1 - d2 - (nd ^ 1); n = r >> 31; z = r == 0; c = nd ? d1 >= d2 : d1 > d2; v = ((d1 ^ d2) & (d1 ^ r)) >> 31; break;
    case 5: n = d1 >> 31; z = d1 == 0; c = d2 & 1; v = nd & 1; break;
    case 6: n = d1 >> 31; z = d1 == 0; c = (nd >> 1) & 1; v = nd & 1; break;
    case 7: n = d2 >> 31; z = (d1 | d2) == 0; c = (nd >> 1) & 1; v = nd & 1; break;
    default: return 0;
  }
  return (n << 31) | (z << 30) | (c << 29) | (v << 28);
}
static inline uint32_t armg_calculate_flag_n(uint32_t op, uint32_t d1, uint32_t d2, uint32_t nd) { return armg_calculate_flags_nzcv(op, d1, d2, nd) >> 31; }
static inline uint32_t armg_calculate_flag_z(uint32_t op, uint32_t d1, uint32_t d2, uint32_t nd) { return (armg_calculate_flags_nzcv(op, d1, d2, nd) >> 30) & 1; }
static inline uint32_t armg_calculate_flag_c(uint32_t op, uint32_t d1, uint32_t d2, uint32_t nd) { return (armg_calculate_flags_nzcv(op, d1, d2, nd) >> 29) & 1; }
static inline uint32_t armg_calculate_flag_v(uint32_t op, uint32_t d1, uint32_t d2, uint32_t nd) { return (armg_calculate_flags_nzcv(op, d1, d2, nd) >> 28) & 1; }
/* cond_n_op: the condition in bits 7-4, the cc_op below. */
static inline uint32_t armg_calculate_condition(uint32_t cond_n_op, uint32_t d1, uint32_t d2, uint32_t nd) {
  uint32_t f = armg_calculate_flags_nzcv(cond_n_op & 0xf, d1, d2, nd);
  uint32_t n = f >> 31, z = (f >> 30) & 1, c = (f >> 29) & 1, v = (f >> 28) & 1, r;
  switch (cond_n_op >> 5) {
    case 0: r = z; break;             /* EQ / NE */
    case 1: r = c; break;             /* HS / LO */
    case 2: r = n; break;             /* MI / PL */
    case 3: r = v; break;             /* VS / VC */
    case 4: r = c & !z; break;        /* HI / LS */
    case 5: r = !(n ^ v); break;      /* GE / LT */
    case 6: r = !z & !(n ^ v); break; /* GT / LE */
    default: return 1;                /* AL */
  }
  return r ^ ((cond_n_op >> 4) & 1);
}
/* ---- AArch64 condition flags, from VEX's thunk (guest_arm64_helpers.c, the codes as angr's ccall.py lists them):
 * cc_op COPY 0 (dep1 holds NZCV in bits 31-28), ADD 1/2, SUB 3/4, ADC 5/6 and SBC 7/8 (ndep: old C), LOGIC 9/10
 * (dep1 the result), each 32 then 64 bits. Results: NZCV in bits 31-28. */
static inline uint64_t arm64g_calculate_flags_nzcv(uint64_t op, uint64_t d1, uint64_t d2, uint64_t nd) {
  if (op == 0) return d1 & 0xf0000000u;
  if (op > 10) return 0;
  int wide = (op % 2) == 0; /* ADD64 2, SUB64 4, ADC64 6, SBC64 8, LOGIC64 10 */
  uint64_t mask = wide ? ~0ULL : 0xffffffffULL, top = wide ? 63 : 31;
  d1 &= mask; d2 &= mask; nd &= 1;
  uint64_t r, n, z, c = 0, v = 0;
  switch ((op + 1) / 2) {
    case 1: r = (d1 + d2) & mask; c = r < d1; v = ((r ^ d1) & (r ^ d2)) >> top & 1; break;
    case 2: r = (d1 - d2) & mask; c = d1 >= d2; v = ((d1 ^ d2) & (d1 ^ r)) >> top & 1; break;
    case 3: r = (d1 + d2 + nd) & mask; c = nd ? r <= d1 : r < d1; v = ((r ^ d1) & (r ^ d2)) >> top & 1; break;
    case 4: r = (d1 - d2 - (nd ^ 1)) & mask; c = nd ? d1 >= d2 : d1 > d2; v = ((d1 ^ d2) & (d1 ^ r)) >> top & 1; break;
    default: r = d1; break; /* LOGIC: C and V clear */
  }
  n = r >> top & 1; z = r == 0;
  return (n << 31) | (z << 30) | (c << 29) | (v << 28);
}
static inline uint64_t arm64g_calculate_flag_c(uint64_t op, uint64_t d1, uint64_t d2, uint64_t nd) {
  return (arm64g_calculate_flags_nzcv(op, d1, d2, nd) >> 29) & 1;
}
/* cond_n_op: the condition in bits 7-4, the cc_op below; conditions in pairs (EQ/NE...), AL and NV always. */
static inline uint64_t arm64g_calculate_condition(uint64_t cond_n_op, uint64_t d1, uint64_t d2, uint64_t nd) {
  uint64_t f = arm64g_calculate_flags_nzcv(cond_n_op & 0xf, d1, d2, nd);
  uint64_t n = f >> 31 & 1, z = f >> 30 & 1, c = f >> 29 & 1, v = f >> 28 & 1, r;
  switch ((cond_n_op >> 5) & 7) {
    case 0: r = z; break;
    case 1: r = c; break;
    case 2: r = n; break;
    case 3: r = v; break;
    case 4: r = c & !z; break;
    case 5: r = !(n ^ v); break;
    case 6: r = !z & !(n ^ v); break;
    default: return 1;
  }
  return r ^ ((cond_n_op >> 4) & 1);
}
#endif
