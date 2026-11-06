/* The guest's operating system, emulated: the stack a Linux process starts with, and the Linux system calls a
 * translated guest makes (atlas_syscall in crosslink.py reads the number and arguments and calls atlas_do_syscall).
 * Guest pointers are offsets into s->mem. System-call numbers are ARM EABI for now (the only cross-link target);
 * another architecture adds its own table. An unimplemented call returns -ENOSYS, as the kernel does for one the
 * guest's C library can do without. Errors are returned as the kernel returns them, -errno in the result register:
 * a host call's -1 is turned into -errno.
 *
 * Guest memory layout (crosslink.py defines the bounds): the image, then the program break growing up from
 * ATLAS_GUEST_BRK, mmap's arena growing up from ATLAS_GUEST_MMAP to ATLAS_GUEST_STACK_LOW, the stack growing down
 * below the start-up block (vector and strings), which ends at ATLAS_GUEST_TOP. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define GUEST(a) ((void *)(s->mem + (uint32_t)(a)))
#define HOST_RESULT(call) ((r = (call)) < 0 ? -errno : r)

static uint32_t atlas_guest_sp;
static uint32_t atlas_brk;       /* the guest program break */
static uint32_t atlas_mmap_next; /* next address handed out by mmap, growing up from the arena */

/* The stack a Linux ELF process starts with: argc, argv, envp, the auxiliary vector, then the strings, ending at
 * ATLAS_GUEST_TOP. Every argument and variable is passed (sized from what the host gives, no fixed limit).
 * AT_RANDOM points at sixteen bytes the C library takes its stack canary and pointer guard from: random, as the
 * kernel gives them, so they are not predictable from outside. */
static void atlas_guest_setup(atlas_state *s, int argc, char **argv, char **envp) {
  int envc = 0;
  while (envp[envc]) envc++;
  size_t strings = 16; /* AT_RANDOM's bytes */
  for (int i = 0; i < argc; i++) strings += strlen(argv[i]) + 1;
  for (int i = 0; i < envc; i++) strings += strlen(envp[i]) + 1;
  uint32_t words = 1 + (argc + 1) + (envc + 1) + 2 * 6; /* argc, argv+NULL, envp+NULL, 6 auxv entries */
  if (strings + words * 4 + 64 > ATLAS_GUEST_TOP - ATLAS_GUEST_STACK_LOW - (1u << 20)) {
    fprintf(stderr, "atlas: arguments and environment too large for the guest stack\n");
    exit(127);
  }
  uint32_t string_at = (uint32_t)((ATLAS_GUEST_TOP - strings) & ~15u);
  uint32_t random_at = string_at;
  if (getrandom(s->mem + random_at, 16, 0) != 16) {
    fprintf(stderr, "atlas: no random bytes for the guest\n");
    exit(127);
  }
  uint32_t at = random_at + 16;
  uint32_t sp = (string_at - words * 4) & ~15u; /* argc lands 16-byte aligned */
  uint32_t *w = (uint32_t *)(s->mem + sp);
  int k = 0;
  w[k++] = (uint32_t)argc;
  for (int i = 0; i < argc; i++) {
    size_t n = strlen(argv[i]) + 1;
    memcpy(s->mem + at, argv[i], n);
    w[k++] = at;
    at += n;
  }
  w[k++] = 0;
  for (int i = 0; i < envc; i++) {
    size_t n = strlen(envp[i]) + 1;
    memcpy(s->mem + at, envp[i], n);
    w[k++] = at;
    at += n;
  }
  w[k++] = 0;
  w[k++] = 25; w[k++] = random_at; /* AT_RANDOM */
  w[k++] = 6;  w[k++] = 4096;      /* AT_PAGESZ */
  w[k++] = 16; w[k++] = 0;         /* AT_HWCAP: no optional features claimed */
  w[k++] = 23; w[k++] = 0;         /* AT_SECURE */
  w[k++] = 11; w[k++] = (uint32_t)getuid(); /* AT_UID */
  w[k++] = 0;  w[k++] = 0;         /* AT_NULL */
  atlas_guest_sp = sp;
  atlas_brk = ATLAS_GUEST_BRK;
  atlas_mmap_next = ATLAS_GUEST_MMAP;
}

/* Whether [a, a + n) lies in guest memory below the stack's region (where the image, brk and mmap live). */
static int atlas_guest_range(uint64_t a, uint64_t n) { return n <= ATLAS_GUEST_STACK_LOW && a <= ATLAS_GUEST_STACK_LOW - n; }

/* mmap2 (ARM's mmap, offset in pages): guest memory from the arena, or at the address asked with MAP_FIXED;
 * zero-filled, then the file's bytes read in for a file mapping (a private copy: writes to it do not reach the
 * file, so MAP_SHARED on a file is refused). */
static long atlas_mmap2(atlas_state *s, uint32_t addr, uint32_t len, uint32_t flags, uint32_t fd, uint32_t pgoff) {
  enum { SHARED = 0x01, FIXED = 0x10, ANONYMOUS = 0x20 };
  if (len == 0) return -EINVAL;
  uint64_t size = ((uint64_t)len + 4095) & ~4095ull;
  int anonymous = (flags & ANONYMOUS) != 0;
  if (!anonymous && (flags & SHARED)) return -ENOSYS;
  uint64_t at;
  if (flags & FIXED) {
    if ((addr & 4095) || !atlas_guest_range(addr, size)) return -EINVAL;
    at = addr;
  } else {
    if (!atlas_guest_range(atlas_mmap_next, size)) return -ENOMEM;
    at = atlas_mmap_next;
    atlas_mmap_next += (uint32_t)size;
  }
  memset(s->mem + at, 0, size);
  if (!anonymous) {
    off_t offset = (off_t)pgoff * 4096;
    for (uint64_t done = 0; done < len;) {
      ssize_t got = pread((int)fd, s->mem + at + done, len - done, offset + (off_t)done);
      if (got < 0) return -errno;
      if (got == 0) break; /* past the file's end: zeros, as the kernel maps them */
      done += (uint64_t)got;
    }
  }
  return (long)at;
}

static void atlas_do_syscall(atlas_state *s, uint32_t n, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
                             uint32_t a4, uint32_t a5, uint32_t *result) {
  long r;
  switch (n) {
    case 1:   /* exit */
    case 248: /* exit_group */
      exit((int)a0);
    case 3: r = HOST_RESULT(read((int)a0, GUEST(a1), a2)); break;
    case 4: r = HOST_RESULT(write((int)a0, GUEST(a1), a2)); break;
    case 146: { /* writev: the guest's iovecs (32-bit base and length) as the host's */
      if (a2 > 1024) { r = -EINVAL; break; }
      struct giovec { uint32_t base, len; } *v = GUEST(a1);
      struct iovec io[1024];
      for (uint32_t i = 0; i < a2; i++) io[i] = (struct iovec){GUEST(v[i].base), v[i].len};
      r = HOST_RESULT(writev((int)a0, io, (int)a2));
      break;
    }
    case 45: /* brk: unchanged (and returned) when asked outside the break's room */
      if (a0 >= ATLAS_GUEST_BRK && a0 < ATLAS_GUEST_MMAP) atlas_brk = a0;
      r = atlas_brk;
      break;
    case 192: r = atlas_mmap2(s, a0, a1, a3, a4, a5); break;
    case 91: r = 0; break;  /* munmap: the memory stays in place (the arena is not reused) */
    case 125: r = 0; break; /* mprotect: guest memory is all readable and writable */
    case 122: {             /* uname */
      struct utsname u;
      memset(&u, 0, sizeof u);
      strcpy(u.sysname, "Linux"); strcpy(u.release, "5.0.0"); strcpy(u.machine, "armv7l");
      memcpy(GUEST(a0), &u, sizeof u);
      r = 0;
      break;
    }
    case 263:   /* clock_gettime: 32-bit tv_sec and tv_nsec */
    case 403: { /* clock_gettime64: 64-bit tv_sec and tv_nsec */
      struct timespec ts;
      r = HOST_RESULT(clock_gettime((clockid_t)a0, &ts));
      if (r == 0 && n == 263) {
        uint32_t g[2] = {(uint32_t)ts.tv_sec, (uint32_t)ts.tv_nsec};
        memcpy(GUEST(a1), g, sizeof g);
      } else if (r == 0) {
        int64_t g[2] = {(int64_t)ts.tv_sec, (int64_t)ts.tv_nsec};
        memcpy(GUEST(a1), g, sizeof g);
      }
      break;
    }
    case 384: r = HOST_RESULT(getrandom(GUEST(a0), a1, a2)); break; /* getrandom */
    case 256: r = 1; break;  /* set_tid_address: the guest's only thread */
    case 338: r = 0; break;  /* set_robust_list */
    case 175: r = 0; break;  /* rt_sigprocmask */
    case 174: case 176: r = 0; break; /* rt_sigaction, rt_sigpending */
    case 20: r = 1; break;   /* getpid */
    default: r = -ENOSYS; break;
  }
  (void)a3;
  *result = (uint32_t)r; /* the kernel's convention: -errno for an error */
}
