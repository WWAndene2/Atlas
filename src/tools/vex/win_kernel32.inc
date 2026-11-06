/* The kernel32 functions a MinGW program's C runtime calls, for one thread and no dynamic libraries
 * (win_base.inc first). Critical sections do nothing (nothing runs concurrently); LoadLibraryExA fails as for a
 * missing DLL, so the program takes its own path without one; memory is all readable, writable and executable, as
 * VirtualQuery reports and VirtualProtect leaves it. GetModuleFileNameA gives the original program's path
 * (winlink.py sets win_module_path) with its last separator written '\\', as Windows separates: a program that
 * cuts its path there to find its directory (Lua's setprogdir) gets the host directory, a valid path here. */
#include <string.h>
#include <unistd.h>

static const char *win_module_path = "";

WIN static void w_InitializeCriticalSection(void *cs) { (void)cs; }
WIN static void w_EnterCriticalSection(void *cs) { (void)cs; }
WIN static void w_LeaveCriticalSection(void *cs) { (void)cs; }
WIN static void w_DeleteCriticalSection(void *cs) { (void)cs; }

WIN static uint32_t w_GetLastError(void) { return 0; }
WIN static void *w_SetUnhandledExceptionFilter(void *filter) { (void)filter; return NULL; }
WIN static void *w_TlsGetValue(uint32_t index) { (void)index; return NULL; }
WIN static void w_Sleep(uint32_t ms) { usleep((useconds_t)ms * 1000); }

WIN static void *w_LoadLibraryExA(const char *name, void *file, uint32_t flags) {
  (void)name; (void)file; (void)flags;
  return NULL;
}
WIN static void *w_GetProcAddress(void *module, const char *name) { (void)module; (void)name; return NULL; }
WIN static int w_FreeLibrary(void *module) { (void)module; return 1; }
WIN static uint32_t w_FormatMessageA(uint32_t flags, const void *source, uint32_t id, uint32_t lang, char *buf,
                                     uint32_t size, void *args) {
  (void)flags; (void)source; (void)id; (void)lang; (void)args;
  if (buf && size) buf[0] = 0;
  return 0; /* no message: the caller keeps its own */
}
WIN static uint32_t w_GetModuleFileNameA(void *module, char *buf, uint32_t size) {
  (void)module;
  size_t n = strlen(win_module_path);
  if (size == 0) return 0;
  /* Too long for the buffer: Windows copies what fits and returns the buffer's size, which callers test for. */
  int truncated = n >= size;
  if (truncated) n = size - 1;
  memcpy(buf, win_module_path, n);
  buf[n] = 0;
  char *last = strrchr(buf, '/');
  if (last) *last = '\\';
  return truncated ? size : (uint32_t)n;
}

/* MEMORY_BASIC_INFORMATION (48 bytes): the page holding the address, committed, PAGE_EXECUTE_READWRITE. */
struct win_memory_info { void *base, *allocation_base; uint32_t allocation_protect, pad0; size_t size;
                         uint32_t state, protect, type, pad1; };
WIN static size_t w_VirtualQuery(const void *at, struct win_memory_info *info, size_t length) {
  if (length < sizeof *info) return 0;
  void *page = (void *)((uintptr_t)at & ~(uintptr_t)0xfff);
  *info = (struct win_memory_info){page, page, 0x40, 0, 0x1000, 0x1000 /* MEM_COMMIT */, 0x40, 0x1000000, 0};
  return sizeof *info;
}
WIN static int w_VirtualProtect(void *at, size_t size, uint32_t protect, uint32_t *old) {
  (void)at; (void)size; (void)protect;
  if (old) *old = 0x40;
  return 1;
}

/* Code pages: single-byte text, each byte one character (what the C runtime asks of them for "C" locale text). */
WIN static int w_IsDBCSLeadByteEx(uint32_t codepage, uint8_t c) { (void)codepage; (void)c; return 0; }
WIN static int w_MultiByteToWideChar(uint32_t cp, uint32_t flags, const char *in, int n, wchar16 *out, int size) {
  (void)cp; (void)flags;
  if (n < 0) n = (int)strlen(in) + 1;
  if (size == 0) return n;
  if (n > size) return 0;
  for (int i = 0; i < n; i++) out[i] = (uint8_t)in[i];
  return n;
}
WIN static int w_WideCharToMultiByte(uint32_t cp, uint32_t flags, const wchar16 *in, int n, char *out, int size,
                                     const char *fallback, int *used) {
  (void)cp; (void)flags; (void)fallback;
  if (n < 0) { n = 0; while (in[n]) n++; n++; }
  if (used) *used = 0;
  if (size == 0) return n;
  if (n > size) return 0;
  for (int i = 0; i < n; i++) {
    out[i] = in[i] < 256 ? (char)in[i] : '?';
    if (in[i] >= 256 && used) *used = 1;
  }
  return n;
}
