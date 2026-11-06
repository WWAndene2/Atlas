/* The guest's operating system, emulated: the stack a Linux process starts with, and the Linux system calls a
 * translated guest makes (atlas_syscall in crosslink.py reads the number and arguments and calls atlas_do_syscall).
 * Guest pointers are offsets into s->mem. System-call numbers are ARM EABI for now (the only cross-link target);
 * another architecture adds its own table. An unimplemented call returns -ENOSYS, as the kernel does for one the
 * guest's C library can do without. */
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>

#define GUEST(a) ((void *)(s->mem + (uint32_t)(a)))

static uint32_t atlas_guest_sp;
static uint32_t atlas_brk;       /* the guest program break */
static uint32_t atlas_mmap_next; /* next address handed out by mmap, growing up from the arena */

/* The stack a Linux ELF process starts with: argc, argv, envp, the auxiliary vector, then the strings. Built near
 * the top of guest memory; AT_RANDOM points at sixteen bytes the C library reads for its stack canary. */
static void atlas_guest_setup(atlas_state *s, int argc, char **argv, char **envp) {
  uint32_t top = ATLAS_GUEST_TOP;
  uint32_t p = top - 4096; /* the strings area, below the top */
  uint32_t string_at = p;
  int envc = 0;
  while (envp[envc]) envc++;
  uint32_t gargv[64], genvp[64];
  for (int i = 0; i < argc && i < 63; i++) {
    size_t n = strlen(argv[i]) + 1;
    memcpy(s->mem + string_at, argv[i], n);
    gargv[i] = string_at;
    string_at += n;
  }
  for (int i = 0; i < envc && i < 63; i++) {
    size_t n = strlen(envp[i]) + 1;
    memcpy(s->mem + string_at, envp[i], n);
    genvp[i] = string_at;
    string_at += n;
  }
  uint32_t random_at = string_at;
  memcpy(s->mem + random_at, "atlas-random-16!", 16);
  string_at += 16;

  /* The vector, laid out downward so argc lands 16-byte aligned. */
  uint32_t words = 1 + (argc + 1) + (envc + 1) + 2 * 6; /* argc, argv+NULL, envp+NULL, 6 auxv entries */
  uint32_t sp = (p - words * 4) & ~15u;
  uint32_t *w = (uint32_t *)(s->mem + sp);
  int k = 0;
  w[k++] = (uint32_t)argc;
  for (int i = 0; i < argc && i < 63; i++) w[k++] = gargv[i];
  w[k++] = 0;
  for (int i = 0; i < envc && i < 63; i++) w[k++] = genvp[i];
  w[k++] = 0;
  w[k++] = 25; w[k++] = random_at;   /* AT_RANDOM */
  w[k++] = 6;  w[k++] = 4096;         /* AT_PAGESZ */
  w[k++] = 16; w[k++] = 0;            /* AT_HWCAP */
  w[k++] = 23; w[k++] = 0;            /* AT_SECURE */
  w[k++] = 11; w[k++] = 1000;         /* AT_UID placeholder; harmless */
  w[k++] = 0;  w[k++] = 0;            /* AT_NULL */
  atlas_guest_sp = sp;
  atlas_brk = ATLAS_GUEST_BRK;
  atlas_mmap_next = ATLAS_GUEST_MMAP;
}

static long atlas_do_syscall(atlas_state *s, uint32_t n, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
                             uint32_t a4, uint32_t a5, uint32_t a6, uint32_t *result) {
  (void)a4; (void)a5; (void)a6;
  long r;
  switch (n) {
    case 1:   /* exit */
    case 248: /* exit_group */
      exit((int)a0);
    case 3: r = read((int)a0, GUEST(a1), a2); break;                 /* read */
    case 4: r = write((int)a0, GUEST(a1), a2); break;                /* write */
    case 146: {                                                      /* writev */
      struct giovec { uint32_t base, len; } *v = GUEST(a1);
      r = 0;
      for (uint32_t i = 0; i < a2; i++) {
        long w = write((int)a0, GUEST(v[i].base), v[i].len);
        if (w < 0) { r = w; break; }
        r += w;
      }
      break;
    }
    case 45: {                                                       /* brk */
      if (a0 == 0 || a0 < ATLAS_GUEST_BRK || a0 >= ATLAS_GUEST_MMAP) { r = atlas_brk; break; }
      atlas_brk = a0;
      r = atlas_brk;
      break;
    }
    case 192: {                                                      /* mmap2: hand out guest memory from the arena */
      uint32_t len = (a1 + 4095) & ~4095u;
      uint32_t at = atlas_mmap_next;
      atlas_mmap_next += len;
      memset(s->mem + at, 0, len);
      r = at;
      break;
    }
    case 91: r = 0; break;                                           /* munmap */
    case 125: r = 0; break;                                          /* mprotect */
    case 122: {                                                      /* uname */
      struct utsname u;
      memset(&u, 0, sizeof u);
      strcpy(u.sysname, "Linux"); strcpy(u.release, "5.0.0"); strcpy(u.machine, "armv7l");
      memcpy(GUEST(a0), &u, sizeof u);
      r = 0;
      break;
    }
    case 263: case 403: {                                            /* clock_gettime / _time64 */
      struct timespec ts;
      clock_gettime((clockid_t)a0, &ts);
      uint32_t *g = GUEST(a1);
      g[0] = (uint32_t)ts.tv_sec; g[1] = (uint32_t)ts.tv_nsec;
      r = 0;
      break;
    }
    case 384: {                                                      /* getrandom */
      uint8_t *p = GUEST(a0);
      for (uint32_t i = 0; i < a1; i++) p[i] = (uint8_t)(i * 1103515245u + 12345u);
      r = a1;
      break;
    }
    case 256: r = 1; break;                                          /* set_tid_address */
    case 338: r = 0; break;                                          /* set_robust_list */
    case 175: r = 0; break;                                          /* rt_sigprocmask */
    case 174: case 176: r = 0; break;                                /* rt_sigaction, rt_sigpending */
    case 20: r = 1; break;                                           /* getpid */
    case 983045: r = 0; break;                                       /* ARM set_tls (0xf0005): TLS set below */
    default: r = -ENOSYS; break;
  }
  if (r < 0 && r >= -4095) *result = (uint32_t)r; /* the kernel returns -errno in the result register */
  else *result = (uint32_t)r;
  return r;
}
