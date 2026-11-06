/* Base of the Windows services (winlink.py): the calling convention and types of the Windows x64 C library, and its
 * three standard streams. Memory is shared with the guest (identity), so a guest pointer is a host pointer; each
 * service is a function with the Windows prototype compiled with the Windows x64 convention (ms_abi), which GCC
 * converts to the host's when it calls the host's C library. */
#include <stdint.h>
#include <stdio.h>

#define WIN __attribute__((ms_abi))
typedef int32_t wlong;     /* long is 32 bits on Windows */
typedef uint16_t wchar16;  /* and wchar_t 16 */

/* msvcrt's _iob: stdin, stdout, stderr, 48 bytes each (MinGW's stdout is &__iob_func()[1]). The guest only takes
 * their addresses; a pointer into one stands for the host's stream. */
static uint8_t win_iob[3 * 48] __attribute__((aligned(16)));

static FILE *win_file(void *p) {
  uint8_t *b = p;
  if (b >= win_iob && b < win_iob + sizeof win_iob) {
    unsigned k = (unsigned)(b - win_iob) / 48;
    return k == 0 ? stdin : k == 1 ? stdout : stderr;
  }
  return p;
}

static void *win_guest_file(FILE *f) {
  if (f == stdin) return win_iob;
  if (f == stdout) return win_iob + 48;
  if (f == stderr) return win_iob + 96;
  return f;
}

WIN static void *w___iob_func(void) { return win_iob; }
