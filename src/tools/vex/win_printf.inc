/* msvcrt's fprintf and vfprintf (win_base.inc first). Windows x64 passes every variadic argument in an 8-byte slot
 * (a double as its bits), and its va_list points at the next slot, so the arguments are read from there. Each
 * conversion is handed to the host's fprintf with the argument at the size Windows gives it: l is 32 bits, I64, ll
 * and I (pointer-sized) 64, h 16, hh 8; with l or w (and in %C, %S) c and s are wide, 16-bit characters. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int win_vformat(FILE *out, const char *format, const uint64_t *slot) {
  int written = 0;
  for (const char *p = format; *p;) {
    if (*p != '%') { fputc(*p++, out); written++; continue; }
    char spec[64];
    size_t k = 0;
    spec[k++] = *p++;
    if (*p == '%') { fputc('%', out); written++; p++; continue; }
    while (*p && strchr("-+ #0", *p) && k < 40) spec[k++] = *p++;          /* flags */
    if (*p == '*') { k += (size_t)snprintf(spec + k, 12, "%d", (int)*slot++); p++; }
    else while (*p >= '0' && *p <= '9' && k < 40) spec[k++] = *p++;        /* width */
    if (*p == '.') {
      spec[k++] = *p++;
      if (*p == '*') { k += (size_t)snprintf(spec + k, 12, "%d", (int)*slot++); p++; }
      else while (*p >= '0' && *p <= '9' && k < 50) spec[k++] = *p++;
    }
    int bits = 32, wide = 0;                                                /* length modifier */
    if (p[0] == 'I' && p[1] == '6' && p[2] == '4') { bits = 64; p += 3; }
    else if (p[0] == 'I' && p[1] == '3' && p[2] == '2') { bits = 32; p += 3; }
    else if (p[0] == 'I') { bits = 64; p++; }
    else if (p[0] == 'l' && p[1] == 'l') { bits = 64; p += 2; }
    else if (p[0] == 'l' || p[0] == 'w') { bits = 32; wide = 1; p++; } /* l or w: also wide c and s */
    else if (p[0] == 'h' && p[1] == 'h') { bits = 8; p += 2; }
    else if (p[0] == 'h') { bits = 16; p++; }
    char c = *p ? *p++ : 0;
    if (c == 'C' || c == 'S') { wide = 1; c = c == 'C' ? 'c' : 's'; } /* msvcrt's wide %C and %S */
    if (c == 0) break;
    uint64_t v = *slot++;
    if (strchr("di", c)) {
      strcpy(spec + k, "lld");
      written += fprintf(out, spec, bits == 64 ? (long long)v : bits == 16 ? (long long)(int16_t)v
                                    : bits == 8 ? (long long)(int8_t)v : (long long)(int32_t)v);
    } else if (strchr("uoxX", c)) {
      spec[k++] = 'l'; spec[k++] = 'l'; spec[k++] = c; spec[k] = 0;
      written += fprintf(out, spec, bits == 64 ? (unsigned long long)v : bits == 16 ? (unsigned long long)(uint16_t)v
                                    : bits == 8 ? (unsigned long long)(uint8_t)v : (unsigned long long)(uint32_t)v);
    } else if (strchr("eEfFgGaA", c)) {
      double d;
      memcpy(&d, &v, sizeof d);
      spec[k++] = c; spec[k] = 0;
      written += fprintf(out, spec, d);
    } else if (c == 'c') {
      spec[k++] = 'c'; spec[k] = 0;
      /* A wide character is 16 bits on Windows: printed as itself when ASCII, else '?'. */
      written += fprintf(out, spec, wide ? ((uint16_t)v < 128 ? (int)(uint16_t)v : '?') : (int)v);
    } else if (c == 's' && wide && v) {
      /* A wide string of 16-bit characters, narrowed the same way (precision counts characters). */
      const wchar16 *w = (const wchar16 *)(uintptr_t)v;
      size_t n = 0;
      while (w[n]) n++;
      char *narrow = malloc(n + 1);
      if (!narrow) return -1;
      for (size_t i = 0; i < n; i++) narrow[i] = w[i] < 128 ? (char)w[i] : '?';
      narrow[n] = 0;
      spec[k++] = 's'; spec[k] = 0;
      written += fprintf(out, spec, narrow);
      free(narrow);
    } else if (c == 's') {
      spec[k++] = 's'; spec[k] = 0;
      written += fprintf(out, spec, v ? (const char *)(uintptr_t)v : "(null)");
    } else if (c == 'p') {
      written += fprintf(out, "%016llX", (unsigned long long)v); /* msvcrt's %p: 16 uppercase hex digits */
    } else {
      slot--; /* not a conversion that takes an argument (%n is not supported): printed as written */
      spec[k++] = c; spec[k] = 0;
      fputs(spec, out);
      written += (int)k;
    }
  }
  return written;
}

WIN static int w_vfprintf(void *f, const char *format, const uint64_t *args) {
  return win_vformat(win_file(f), format, args);
}
WIN static int w_fprintf(void *f, const char *format, ...) {
  __builtin_ms_va_list ap;
  __builtin_ms_va_start(ap, format);
  int n = win_vformat(win_file(f), format, (const uint64_t *)ap);
  __builtin_ms_va_end(ap);
  return n;
}
