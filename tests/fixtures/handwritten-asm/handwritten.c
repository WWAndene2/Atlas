/* Hand-written assembly patterns a console game uses and a function-by-function translation may not follow, for
 * the 3DS's CPU (ARMv6K, ARM state), freestanding (its own _start, Linux system calls by hand so the ARM cross-link
 * runs it). Built once per pattern (-DPATTERN=1, 2 or 3); the program writes "ok\n" when the pattern's result is
 * right and "no\n" otherwise, then exits 0.
 *   1. A call made by hand: adr lr to the return point, then b to the callee (no bl).
 *   2. A return that skips a level: the innermost function pops the return address its caller saved, so control
 *      goes back to its caller's caller.
 *   3. A stack switch: a call run on another stack, then the original stack restored. */
static long sys(long n, long a, long b, long c) {
  register long r7 __asm__("r7") = n;
  register long r0 __asm__("r0") = a;
  register long r1 __asm__("r1") = b;
  register long r2 __asm__("r2") = c;
  __asm__ volatile("svc 0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2) : "memory");
  return r0;
}

#if PATTERN == 1
__attribute__((naked, noinline)) int plus_ten(int x) { __asm__("add r0, r0, #10\n bx lr\n"); }
__attribute__((naked, noinline)) int pattern(int x) {
  __asm__("push {r4, lr}\n adr lr, 1f\n b plus_ten\n1: add r0, r0, #1\n pop {r4, pc}\n");
}
#define INPUT 5
#define EXPECTED 16
#elif PATTERN == 2
__attribute__((naked, noinline)) int skip_c(int x) { __asm__("add r0, r0, #100\n pop {r4, pc}\n"); }
__attribute__((naked, noinline)) int pattern(int x) {
  __asm__("push {r4, lr}\n bl skip_c\n mov r0, #0\n pop {r4, pc}\n"); /* the mov is never reached */
}
#define INPUT 1
#define EXPECTED 101
#else
static unsigned char other_stack[4096] __attribute__((aligned(8)));
__attribute__((noinline)) int deep(int x) {
  volatile int pad[16];
  for (int i = 0; i < 16; i++) pad[i] = x + i;
  return pad[15];
}
__attribute__((naked, noinline)) int switch_stack(int x, void *top) {
  __asm__("push {r4, lr}\n mov r4, sp\n mov sp, r1\n bl deep\n mov sp, r4\n pop {r4, pc}\n");
}
int pattern(int x) { return switch_stack(x, other_stack + sizeof other_stack); }
#define INPUT 3
#define EXPECTED 18
#endif

void _start_c(void) {
  sys(4, 1, (long)(pattern(INPUT) == EXPECTED ? "ok\n" : "no\n"), 3);
  sys(1, 0, 0, 0);
}
__attribute__((naked)) void _start(void) { __asm__("bl _start_c\n"); }
