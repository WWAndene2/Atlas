"""setjmp and longjmp for translated code, shared by the linker (link.py) and the behaviour check (check_lifted.py).

A guest's setjmp must run the host's setjmp in the translated caller's own frame, so that a later longjmp lands
back in it while it is alive, as in C: SETJMP_HEADER, included before every translation, expands ATLAS_CALL there.
jumps_c gives the support code: a host jmp_buf per guest jmp_buf, with the guest registers setjmp saw, restored when
longjmp lands, and longjmp_guest for the longjmp imports. x86-64 System V registers.
"""

SETJMP_HEADER = """#include <setjmp.h>
#include <stdint.h>
struct atlas_state;
int atlas_is_setjmp(uint64_t target);
void *atlas_jump_buf(struct atlas_state *s);
void atlas_jump_first(struct atlas_state *s);
void atlas_jump_back(struct atlas_state *s);
#define ATLAS_CALL(t) do { uint64_t t_ = (t); if (atlas_is_setjmp(t_)) { \\
    if (setjmp(*(jmp_buf *)atlas_jump_buf(s))) atlas_jump_back(s); else atlas_jump_first(s); \\
  } else atlas_call(s, t_); } while (0)
"""

# The import names that start and end a jump.
SETJMP_NAMES = ("_setjmp", "setjmp", "__sigsetjmp")
LONGJMP_NAMES = ("__longjmp_chk", "longjmp", "_longjmp", "siglongjmp")


def jumps_c(off):
    """The support code, `off` giving a register's offset in the guest state."""
    saved = ", ".join(str(off(r)) for r in ("rsp", "rbp", "rbx", "r12", "r13", "r14", "r15", "rax"))
    rdi, rsi, rax, rsp = off("rdi"), off("rsi"), off("rax"), off("rsp")
    return f"""
#include <stdio.h>
struct jump {{ uint64_t guest; jmp_buf host; uint64_t regs[8]; uint64_t value; }};
static struct jump jumps[4096];
static struct jump *landing;
static const int jump_saved[8] = {{{saved}}};
/* The entry for a guest jmp_buf: its own, else a free one, else one whose jmp_buf lies below the stack pointer (on
 * the guest stack, which grows down, that frame has returned: the buffer is dead; coroutines and deep pcalls make
 * many). */
static struct jump *jump_for(atlas_state *s, uint64_t guest) {{
  struct jump *free_one = 0;
  uint64_t sp = REG(uint64_t, {rsp});
  for (int i = 0; i < 4096; i++) {{
    if (jumps[i].guest == guest) return &jumps[i];
    if (!free_one && (jumps[i].guest == 0 || jumps[i].guest < sp)) free_one = &jumps[i];
  }}
  if (!free_one) {{ fprintf(stderr, "atlas: more than 4096 live setjmp buffers\\n"); abort(); }}
  free_one->guest = guest;
  return free_one;
}}
static void longjmp_guest(atlas_state *s) {{
  struct jump *j = jump_for(s, REG(uint64_t, {rdi}));
  j->value = REG(uint64_t, {rsi}) ? REG(uint64_t, {rsi}) : 1;
  landing = j;
  longjmp(j->host, 1);
}}
void *atlas_jump_buf(atlas_state *s) {{
  struct jump *j = jump_for(s, REG(uint64_t, {rdi}));
  for (int k = 0; k < 8; k++) j->regs[k] = REG(uint64_t, jump_saved[k]);
  return &j->host;
}}
/* setjmp's first return: 0, and the return address the guest's call pushed popped. */
void atlas_jump_first(atlas_state *s) {{ REG(uint64_t, {rax}) = 0; REG(uint64_t, {rsp}) += 8; }}
/* Back from a longjmp: the registers as setjmp saw them, the value longjmp passed. */
void atlas_jump_back(atlas_state *s) {{
  for (int k = 0; k < 8; k++) REG(uint64_t, jump_saved[k]) = landing->regs[k];
  REG(uint64_t, {rax}) = landing->value;
  REG(uint64_t, {rsp}) += 8;
}}
"""
