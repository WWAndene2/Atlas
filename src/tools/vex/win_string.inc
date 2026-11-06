/* msvcrt's string, memory, character-class, allocation and math functions: the same in both C libraries, so each
 * service only changes the calling convention (win_base.inc first). wcslen counts Windows' 16-bit wchar_t. */
#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

WIN static void *w_malloc(size_t n) { return malloc(n); }
WIN static void *w_calloc(size_t n, size_t k) { return calloc(n, k); }
WIN static void *w_realloc(void *p, size_t n) { return realloc(p, n); }
WIN static void w_free(void *p) { free(p); }

WIN static void *w_memcpy(void *d, const void *s, size_t n) { return memcpy(d, s, n); }
WIN static void *w_memmove(void *d, const void *s, size_t n) { return memmove(d, s, n); }
WIN static void *w_memset(void *d, int c, size_t n) { return memset(d, c, n); }
WIN static int w_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
WIN static void *w_memchr(const void *s, int c, size_t n) { return memchr(s, c, n); }
WIN static size_t w_strlen(const char *s) { return strlen(s); }
WIN static int w_strcmp(const char *a, const char *b) { return strcmp(a, b); }
WIN static int w_strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); }
WIN static int w_strcoll(const char *a, const char *b) { return strcoll(a, b); }
WIN static char *w_strchr(const char *s, int c) { return strchr(s, c); }
WIN static char *w_strrchr(const char *s, int c) { return strrchr(s, c); }
WIN static char *w_strstr(const char *a, const char *b) { return strstr(a, b); }
WIN static char *w_strpbrk(const char *a, const char *b) { return strpbrk(a, b); }
WIN static size_t w_strspn(const char *a, const char *b) { return strspn(a, b); }
WIN static size_t w_wcslen(const wchar16 *s) {
  size_t n = 0;
  while (s[n]) n++;
  return n;
}

WIN static int w_isalnum(int c) { return isalnum(c); }
WIN static int w_isalpha(int c) { return isalpha(c); }
WIN static int w_iscntrl(int c) { return iscntrl(c); }
WIN static int w_isgraph(int c) { return isgraph(c); }
WIN static int w_islower(int c) { return islower(c); }
WIN static int w_ispunct(int c) { return ispunct(c); }
WIN static int w_isspace(int c) { return isspace(c); }
WIN static int w_isupper(int c) { return isupper(c); }
WIN static int w_isxdigit(int c) { return isxdigit(c); }
WIN static int w_tolower(int c) { return tolower(c); }
WIN static int w_toupper(int c) { return toupper(c); }

WIN static double w_acos(double x) { return acos(x); }
WIN static double w_asin(double x) { return asin(x); }
WIN static double w_tan(double x) { return tan(x); }
WIN static double w_log10(double x) { return log10(x); }
