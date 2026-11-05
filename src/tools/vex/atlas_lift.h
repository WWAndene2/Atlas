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
} atlas_state;

void atlas_call(atlas_state *s, uint64_t target);
/* A trap the guest raised (division by zero, ud2, breakpoint): the program decides what it does. */
void atlas_trap(atlas_state *s, uint64_t at, int kind);

#define REG(T, off) (*(T *)(s->r + (off)))
#ifndef ATLAS_HOST
#define ATLAS_HOST(a) (s->mem + (uint64_t)(a))
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
#define ATLAS_LOAD(N)                                                         \
  static inline uint##N##_t atlas_load##N(atlas_state *s, uint64_t a) {       \
    uint##N##_t v;                                                            \
    if (ATLAS_OUTSIDE(a, sizeof v)) return 0;                                 \
    memcpy(&v, ATLAS_HOST(a), sizeof v);                                      \
    return SWAP##N(v);                                                        \
  }                                                                           \
  static inline void atlas_store##N(atlas_state *s, uint64_t a, uint##N##_t v) { \
    if (ATLAS_OUTSIDE(a, sizeof v)) return;                                   \
    v = SWAP##N(v);                                                           \
    memcpy(ATLAS_HOST(a), &v, sizeof v);                                      \
  }
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
static inline double atlas_sqrtf64(uint32_t rm, double a) { (void)rm; return sqrt(a); }

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
#endif
