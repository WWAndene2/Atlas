/* msvcrt's time functions (win_base.inc first). Windows' struct tm is nine ints; glibc's adds two fields after
 * them, so a guest struct tm is copied into a host one before the host reads it, and results are copied out to a
 * buffer of the Windows size. clock() counts milliseconds on Windows (CLOCKS_PER_SEC 1000). */
#include <string.h>
#include <time.h>

struct win_tm { int sec, min, hour, mday, mon, year, wday, yday, isdst; };

static struct tm win_to_host_tm(const struct win_tm *w) {
  struct tm t;
  memset(&t, 0, sizeof t);
  t.tm_sec = w->sec; t.tm_min = w->min; t.tm_hour = w->hour; t.tm_mday = w->mday; t.tm_mon = w->mon;
  t.tm_year = w->year; t.tm_wday = w->wday; t.tm_yday = w->yday; t.tm_isdst = w->isdst;
  return t;
}

static struct win_tm win_tm_result;
static struct win_tm *win_from_host_tm(const struct tm *t) {
  if (!t) return NULL;
  win_tm_result = (struct win_tm){t->tm_sec, t->tm_min, t->tm_hour, t->tm_mday, t->tm_mon,
                                  t->tm_year, t->tm_wday, t->tm_yday, t->tm_isdst};
  return &win_tm_result;
}

WIN static int64_t w__time64(int64_t *out) {
  int64_t now = (int64_t)time(NULL);
  if (out) *out = now;
  return now;
}
WIN static struct win_tm *w__localtime64(const int64_t *t) {
  time_t v = (time_t)*t;
  return win_from_host_tm(localtime(&v));
}
WIN static struct win_tm *w__gmtime64(const int64_t *t) {
  time_t v = (time_t)*t;
  return win_from_host_tm(gmtime(&v));
}
WIN static int64_t w__mktime64(struct win_tm *w) {
  struct tm t = win_to_host_tm(w);
  int64_t r = (int64_t)mktime(&t);
  if (r != -1) *w = *win_from_host_tm(&t); /* mktime normalises the fields it was given */
  return r;
}
WIN static double w__difftime64(int64_t a, int64_t b) { return (double)(a - b); }
WIN static int32_t w_clock(void) { return (int32_t)(clock() / (CLOCKS_PER_SEC / 1000)); }
WIN static size_t w_strftime(char *out, size_t n, const char *format, const struct win_tm *w) {
  struct tm t = win_to_host_tm(w);
  return strftime(out, n, format, &t);
}
