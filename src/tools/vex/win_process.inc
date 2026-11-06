/* msvcrt's process, environment and locale functions (win_base.inc first). system() and _pclose() return the
 * command's exit code on Windows, not a wait status. Signals are recorded, not delivered (the guest's handlers are
 * guest code): signal() returns the previous handler as Windows would. One thread: _lock and _unlock do nothing. */
#include <errno.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int win_exit_code(int status) { return status == -1 ? -1 : WIFEXITED(status) ? WEXITSTATUS(status) : 1; }

WIN static char *w_getenv(const char *name) { return getenv(name); }
WIN static int w_system(const char *command) {
  int status = system(command);
  return command ? win_exit_code(status) : status;
}
WIN static void *w__popen(const char *command, const char *mode) {
  char host[4] = {0};
  for (int i = 0, k = 0; mode[i] && k < 2; i++) /* Windows' 'b' and 't' are not popen modes on Linux */
    if (mode[i] == 'r' || mode[i] == 'w') host[k++] = mode[i];
  return popen(command, host);
}
WIN static int w__pclose(void *f) { return win_exit_code(pclose(f)); }
WIN static void w_abort(void) { abort(); }

WIN static int *w__errno(void) { return &errno; }
WIN static char *w_strerror(int e) { return strerror(e); }
WIN static char *w_setlocale(int category, const char *name) { return setlocale(category, name); }
/* Lua reads only decimal_point, the first field of both structures. */
WIN static struct lconv *w_localeconv(void) { return localeconv(); }
WIN static int w____mb_cur_max_func(void) { return 1; }
WIN static unsigned w____lc_codepage_func(void) { return 0; }

static void *win_signal_handlers[32];
WIN static void *w_signal(int sig, void *handler) {
  if (sig < 0 || sig >= 32) return (void *)(intptr_t)-1; /* SIG_ERR */
  void *previous = win_signal_handlers[sig];
  win_signal_handlers[sig] = handler;
  return previous;
}

/* msvcrt's tmpnam writes into a buffer of L_tmpnam bytes, 14 for MinGW: the name must fit, NUL included
 * ("/tmp/a" and 7 hex digits from the process and a counter: 13 characters). */
#define WIN_L_TMPNAM 14
WIN static char *w_tmpnam(char *out) {
  static char name[WIN_L_TMPNAM];
  static unsigned counter;
  char *to = out ? out : name;
  snprintf(to, WIN_L_TMPNAM, "/tmp/a%07x", ((unsigned)getpid() * 4099u + counter++) & 0xfffffffu);
  return to;
}

WIN static void w__lock(int n) { (void)n; }
WIN static void w__unlock(int n) { (void)n; }
WIN static void w___set_app_type(int t) { (void)t; }
WIN static void w___setusermatherr(void *f) { (void)f; }

/* Data msvcrt exports: the guest reads them through its import slots, which hold their addresses. */
static int win_commode, win_fmode;
static char **win_initenv;
