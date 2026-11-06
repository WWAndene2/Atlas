/* msvcrt's fprintf and vfprintf (win_base.inc first). Windows x64 passes every variadic argument in an 8-byte slot
 * (a double as its bits), and its va_list points at the next slot, so the arguments are read from there. Each
 * conversion is handed to the host's fprintf with the argument at the size Windows gives it: l is 32 bits, I64, ll
 * and I (pointer-sized) 64, h 16. */
#include <stdarg.h>
#include <stdio.h>
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
    int bits = 32;                                                          /* length modifier */
    if (p[0] == 'I' && p[1] == '6' && p[2] == '4') { bits = 64; p += 3; }
    else if (p[0] == 'I' && p[1] == '3' && p[2] == '2') { bits = 32; p += 3; }
    else if (p[0] == 'I') { bits = 64; p++; }
    else if (p[0] == 'l' && p[1] == 'l') { bits = 64; p += 2; }
    else if (p[0] == 'l') { bits = 32; p++; }
    else if (p[0] == 'h') { bits = 16; p++; }
    char c = *p ? *p++ : 0;
    if (c == 0) break;
    uint64_t v = *slot++;
    if (strchr("di", c)) {
      strcpy(spec + k, "lld");
      written += fprintf(out, spec, bits == 64 ? (long long)v : bits == 16 ? (long long)(int16_t)v : (long long)(int32_t)v);
    } else if (strchr("uoxX", c)) {
      spec[k++] = 'l'; spec[k++] = 'l'; spec[k++] = c; spec[k] = 0;
      written += fprintf(out, spec, bits == 64 ? (unsigned long long)v : bits == 16 ? (unsigned long long)(uint16_t)v
                                                                                : (unsigned long long)(uint32_t)v);
    } else if (strchr("eEfFgGaA", c)) {
      double d;
      memcpy(&d, &v, sizeof d);
      spec[k++] = c; spec[k] = 0;
      written += fprintf(out, spec, d);
    } else if (c == 'c') {
      spec[k++] = 'c'; spec[k] = 0;
      written += fprintf(out, spec, (int)v);
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
