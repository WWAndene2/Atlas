/* The console kernel's core, shared by every console (docs/ROADMAP.md, "Focus"): kernel objects behind handles,
 * a registry of services, and a log of everything a program asked for that is not served. It knows no console: a
 * profile (console/ctr.inc for the 3DS) maps its machine's system calls, IPC format and services onto it. Included
 * by the linked program after atlas_lift.h; one thread for now. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Kernel objects behind handles. */
enum console_kind { CONSOLE_FREE, CONSOLE_SESSION, CONSOLE_PORT, CONSOLE_EVENT, CONSOLE_MUTEX, CONSOLE_SEMAPHORE,
                    CONSOLE_MEMORY, CONSOLE_THREAD, CONSOLE_OTHER };

struct console_service;
struct console_object {
  enum console_kind kind;
  uint64_t value;                    /* the object's state: an event's signal, a mutex's owner, a memory block's address */
  const struct console_service *service; /* a session's or a port's service */
  uint32_t count, limit;             /* a semaphore's count and maximum, an event's state and reset (threads.inc) */
};

#define CONSOLE_HANDLES 4096
#define CONSOLE_HANDLE_BASE 0x100      /* handle values a program sees: never 0, never a small integer it may misuse */
static struct console_object console_objects[CONSOLE_HANDLES];

/* A new handle to a new object, or 0 when the table is full. */
static uint32_t console_handle_new(enum console_kind kind, uint64_t value, const struct console_service *service) {
  for (uint32_t k = 1; k < CONSOLE_HANDLES; k++) {
    if (console_objects[k].kind == CONSOLE_FREE) {
      console_objects[k] = (struct console_object){kind, value, service};
      return CONSOLE_HANDLE_BASE + k;
    }
  }
  return 0;
}

/* The object behind a handle, or NULL for a handle the kernel did not give or that was closed. */
static struct console_object *console_handle_get(uint32_t handle) {
  uint32_t k = handle - CONSOLE_HANDLE_BASE;
  if (handle < CONSOLE_HANDLE_BASE || k >= CONSOLE_HANDLES || console_objects[k].kind == CONSOLE_FREE) return NULL;
  return &console_objects[k];
}

static int console_handle_close(uint32_t handle) {
  struct console_object *o = console_handle_get(handle);
  if (o == NULL) return 0;
  o->kind = CONSOLE_FREE;
  return 1;
}

/* ---- Services: a name, and the function that serves one request on a session to it. The request is the
 * profile's command buffer (its format is the profile's), in guest memory; the handler writes the reply there. */
typedef void (*console_handler)(atlas_state *s, uint8_t *command, struct console_object *session);
struct console_service {
  const char *name;
  console_handler handler; /* NULL: a service the program may connect to, whose requests are all unserved */
};

#define CONSOLE_SERVICES 128
static struct console_service console_services[CONSOLE_SERVICES];
static int console_service_count;

static const struct console_service *console_service_find(const char *name) {
  for (int k = 0; k < console_service_count; k++)
    if (strcmp(console_services[k].name, name) == 0) return &console_services[k];
  return NULL;
}

/* A service by name, registered with no handler when the profile did not register one (so that a program can still
 * get a session to it, and every request it sends is logged as unserved). */
static const struct console_service *console_service_lookup(const char *name) {
  const struct console_service *found = console_service_find(name);
  if (found != NULL || console_service_count == CONSOLE_SERVICES) return found;
  char *copy = strdup(name);
  console_services[console_service_count] = (struct console_service){copy, NULL};
  return &console_services[console_service_count++];
}

static void console_service_register(const char *name, console_handler handler) {
  struct console_service *found = (struct console_service *)console_service_find(name);
  if (found != NULL) found->handler = handler;
  else if (console_service_count < CONSOLE_SERVICES)
    console_services[console_service_count++] = (struct console_service){name, handler};
}

/* ---- What the program asked for that is not served: what (a system call, a service's command, an import, a
 * register), which one, how many times. Written at exit, most asked first: what a title needs, read rather than
 * guessed. ATLAS_UNSERVED=<file>: one line each, "count what id"; otherwise a summary on standard error. */
struct console_unserved_entry { const char *what; uint32_t id; uint64_t count; int first; };
#define CONSOLE_UNSERVED 1024
static struct console_unserved_entry console_unserved_log[CONSOLE_UNSERVED];
static int console_unserved_count;

static void console_unserved(const char *what, uint32_t id) {
  for (int k = 0; k < console_unserved_count; k++) {
    if (console_unserved_log[k].id == id && strcmp(console_unserved_log[k].what, what) == 0) {
      console_unserved_log[k].count++;
      return;
    }
  }
  if (console_unserved_count < CONSOLE_UNSERVED)
    console_unserved_log[console_unserved_count++] = (struct console_unserved_entry){strdup(what), id, 1, console_unserved_count};
}

static int console_unserved_order(const void *a, const void *b) {
  const struct console_unserved_entry *x = a, *y = b;
  if (x->count != y->count) return x->count < y->count ? 1 : -1;
  return x->first - y->first; /* equal counts: in the order first asked (qsort alone is not stable) */
}

static void console_unserved_write(void) {
  if (console_unserved_count == 0) return;
  qsort(console_unserved_log, (size_t)console_unserved_count, sizeof console_unserved_log[0], console_unserved_order);
  const char *path = getenv("ATLAS_UNSERVED");
  FILE *out = path != NULL ? fopen(path, "w") : stderr;
  if (out == NULL) return;
  if (path == NULL) fprintf(out, "atlas: not served (count, what, id):\n");
  for (int k = 0; k < console_unserved_count; k++)
    fprintf(out, "%llu %s %#x\n", (unsigned long long)console_unserved_log[k].count, console_unserved_log[k].what,
            console_unserved_log[k].id);
  if (out != stderr) fclose(out);
}
