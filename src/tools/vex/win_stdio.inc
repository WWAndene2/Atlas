/* msvcrt's file functions over the host's (win_base.inc first): streams converted with win_file, Windows' 32-bit
 * long for ftell and fseek, and setvbuf's Windows modes (_IOFBF 0, _IOLBF 0x40, _IONBF 4). */
#include <stdio.h>
#include <unistd.h>

WIN static void *w_fopen(const char *path, const char *mode) { return win_guest_file(fopen(path, mode)); }
WIN static void *w_freopen(const char *path, const char *mode, void *f) {
  return win_guest_file(freopen(path, mode, win_file(f)));
}
WIN static int w_fclose(void *f) { return fclose(win_file(f)); }
WIN static int w_fflush(void *f) { return fflush(f ? win_file(f) : NULL); }
WIN static size_t w_fread(void *p, size_t n, size_t k, void *f) { return fread(p, n, k, win_file(f)); }
WIN static size_t w_fwrite(const void *p, size_t n, size_t k, void *f) { return fwrite(p, n, k, win_file(f)); }
WIN static int w_fseek(void *f, wlong off, int whence) { return fseek(win_file(f), off, whence); }
WIN static wlong w_ftell(void *f) { return (wlong)ftell(win_file(f)); }
WIN static int w_getc(void *f) { return getc(win_file(f)); }
WIN static int w_ungetc(int c, void *f) { return ungetc(c, win_file(f)); }
WIN static int w_fputc(int c, void *f) { return fputc(c, win_file(f)); }
WIN static int w_fputs(const char *s, void *f) { return fputs(s, win_file(f)); }
WIN static char *w_fgets(char *s, int n, void *f) { return fgets(s, n, win_file(f)); }
WIN static int w_feof(void *f) { return feof(win_file(f)); }
WIN static int w_ferror(void *f) { return ferror(win_file(f)); }
WIN static void w_clearerr(void *f) { clearerr(win_file(f)); }
WIN static int w__fileno(void *f) { return fileno(win_file(f)); }
WIN static int w__isatty(int fd) { return isatty(fd); }
WIN static void *w_tmpfile(void) { return win_guest_file(tmpfile()); }
WIN static int w_remove(const char *p) { return remove(p); }
WIN static int w_rename(const char *a, const char *b) { return rename(a, b); }

WIN static int w_setvbuf(void *f, char *buf, int mode, size_t size) {
  int host = mode == 4 ? _IONBF : mode == 0x40 ? _IOLBF : _IOFBF;
  return setvbuf(win_file(f), buf, host, size);
}
