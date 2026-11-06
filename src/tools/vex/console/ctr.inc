/* The 3DS profile of the console kernel (console/kernel.inc): Horizon's system calls, its IPC command format, and its
 * service registry, srv:. Included by crosslink.py's program when the request's profile is "ctr", after it defines
 * ctr_reg (the guest offsets of r0 to r5) and CTR_TLS_REG and CTR_SP_REG (TPIDRURO's and sp's), and after console/threads.inc.
 *
 * Horizon's convention: the call's number is the svc instruction's immediate (s->svc); arguments in r0 to r3 (r4
 * for a fifth), the result code in r0, outputs in r1 and up. A thread's command buffer is at its TLS + 0x80; a
 * request's header is (command << 16) | (normal words << 6) | translate words, and the reply is written over it.
 *
 * What is not served returns CTR_NOT_IMPLEMENTED and is logged (console_unserved): a title's needs are read from the
 * log, not guessed. Success is not faked, so a title that checks results takes its own error path rather than
 * running on with nothing behind it. Threads, waits and their objects are the core's (threads.inc): a thread runs
 * until it blocks, yields or readies a higher-priority one, as on the application core. */
#include <time.h>

#define CTR_R(n) REG(uint32_t, ctr_reg[n])
#define CTR_OK 0u
#define CTR_NOT_IMPLEMENTED 0xF8C007F4u /* Horizon's "not implemented" (level permanent, summary not supported) */
#define CTR_INVALID_HANDLE 0xD8E007F7u
#define CTR_TIMEOUT 0x09401BFEu
#define CTR_NOT_OWNER 0xD8E0041Fu       /* releasing a mutex another thread holds (not checked on the hardware) */
#define CTR_OUT_OF_RANGE 0xE0E01BFDu    /* releasing a semaphore past its maximum (not checked on the hardware) */
#define CTR_CURRENT_THREAD 0xFFFF8000u  /* the pseudo-handle naming the calling thread */
#define CTR_MAIN_PRIORITY 0x30          /* a title's usual main-thread priority (its exheader gives the real one) */

/* The guest's memory, at the 3DS's own addresses (all mapped already: committing memory only hands out addresses). */
#define CTR_HEAP 0x08000000u
#define CTR_LINEAR 0x14000000u
#define CTR_STACK_TOP 0x10000000u
#define CTR_TLS 0x1FF82000u /* thread k's storage at CTR_TLS + 0x200 * k */
static uint32_t ctr_heap_next = CTR_HEAP, ctr_linear_next = CTR_LINEAR;

static uint32_t *ctr_command(atlas_state *s) { return (uint32_t *)(s->mem + REG(uint32_t, CTR_TLS_REG) + 0x80); }
static int64_t ctr_timeout(uint32_t low, uint32_t high) { return (int64_t)(((uint64_t)high << 32) | low); }

/* ---- srv:, the service registry. RegisterClient (1) and GetServiceHandle (5) are served; a handle is given for any
 * name, to a registered service or to one with no handler, so the title's requests to it are logged one by one. */
static void ctr_srv(atlas_state *s, uint8_t *command, struct console_object *session) {
  (void)s;
  (void)session;
  uint32_t *c = (uint32_t *)command, id = c[0] >> 16;
  if (id == 0x0001) {
    c[0] = 0x00010040;
    c[1] = CTR_OK;
  } else if (id == 0x0005) {
    char name[9] = {0};
    uint32_t length = c[3] < 8 ? c[3] : 8;
    memcpy(name, &c[1], length);
    uint32_t handle = console_handle_new(CONSOLE_SESSION, 0, console_service_lookup(name));
    c[0] = 0x00050042;
    c[1] = handle ? CTR_OK : CTR_NOT_IMPLEMENTED;
    c[2] = 0x04000000; /* a copied handle follows */
    c[3] = handle;
  } else {
    console_unserved("srv:", id);
    c[0] = (id << 16) | 0x40;
    c[1] = CTR_NOT_IMPLEMENTED;
  }
}

static void ctr_setup(atlas_state *s) {
  REG(uint32_t, CTR_TLS_REG) = CTR_TLS;
  console_service_register("srv:", ctr_srv);
  atexit(console_unserved_write);
  console_threads_start(s, CTR_MAIN_PRIORITY);
}

/* The thread a handle names (the calling thread for the pseudo-handle), or -1. */
static int ctr_thread(uint32_t handle) {
  if (handle == CTR_CURRENT_THREAD) return console_self;
  struct console_object *o = console_handle_get(handle);
  return o != NULL && o->kind == CONSOLE_THREAD ? (int)o->value : -1;
}

/* An object of a kind from a handle, or NULL. */
static struct console_object *ctr_object(uint32_t handle, enum console_kind kind) {
  struct console_object *o = console_handle_get(handle);
  return o != NULL && o->kind == kind ? o : NULL;
}

/* SendSyncRequest: the session's service serves the command buffer, or the command is logged under its name. */
static uint32_t ctr_request(atlas_state *s, uint32_t handle) {
  struct console_object *o = console_handle_get(handle);
  if (o == NULL || o->kind != CONSOLE_SESSION) return CTR_INVALID_HANDLE;
  uint32_t *c = ctr_command(s);
  if (o->service->handler != NULL) {
    o->service->handler(s, (uint8_t *)c, o);
  } else {
    uint32_t id = c[0] >> 16;
    console_unserved(o->service->name, id);
    c[0] = (id << 16) | 0x40;
    c[1] = CTR_NOT_IMPLEMENTED;
  }
  return CTR_OK;
}

static void ctr_syscall(atlas_state *s) {
  uint32_t r = CTR_OK;
  switch (s->svc) {
    case 0x01: { /* ControlMemory(op, addr0, addr1, size, permissions): commit hands out addresses, free succeeds */
      uint32_t op = CTR_R(0) & 0xFF, size = (CTR_R(3) + 0xFFF) & ~0xFFFu;
      if (op == 3) {
        uint32_t *next = (CTR_R(0) & 0x10000) ? &ctr_linear_next : &ctr_heap_next;
        uint32_t at = CTR_R(1) && !(CTR_R(0) & 0x10000) ? CTR_R(1) : *next;
        if (at + size > *next) *next = at + size;
        CTR_R(1) = at;
      } else if (op != 1) {
        console_unserved("svc ControlMemory op", op);
        r = CTR_NOT_IMPLEMENTED;
      }
      break;
    }
    case 0x03: exit(0); /* ExitProcess */
    case 0x08: { /* CreateThread(priority, entry, argument, stack top, processor): out r1 the thread's handle */
      int k = console_thread_new((int)CTR_R(0), CTR_R(1));
      uint32_t handle = k < 0 ? 0 : console_handle_new(CONSOLE_THREAD, (uint64_t)k, NULL);
      if (handle == 0) {
        if (k >= 0) console_threads[k].state = CONSOLE_THREAD_FREE;
        r = CTR_NOT_IMPLEMENTED;
        break;
      }
      { /* the new thread's registers: a copy of these, so r2 and r3 still hold its argument and stack top */
        atlas_state *s = console_threads[k].s;
        CTR_R(0) = CTR_R(2);
        REG(uint32_t, CTR_SP_REG) = CTR_R(3) & ~7u; /* aligned as the ABI wants */
        REG(uint32_t, CTR_TLS_REG) = CTR_TLS + 0x200u * (uint32_t)k;
      }
      CTR_R(1) = handle;
      if (!console_thread_go(k)) r = CTR_NOT_IMPLEMENTED;
      break;
    }
    case 0x09: console_thread_exit(); break; /* ExitThread */
    case 0x0A: console_sleep((int64_t)ctr_timeout(CTR_R(0), CTR_R(1))); break; /* SleepThread(nanoseconds) */
    case 0x0B: { /* GetThreadPriority(thread): out r1 */
      int k = ctr_thread(CTR_R(1));
      if (k < 0) r = CTR_INVALID_HANDLE;
      else CTR_R(1) = (uint32_t)console_threads[k].priority;
      break;
    }
    case 0x0C: { /* SetThreadPriority(thread, priority) */
      int k = ctr_thread(CTR_R(0));
      if (k < 0) r = CTR_INVALID_HANDLE;
      else {
        console_threads[k].priority = (int)CTR_R(1);
        console_schedule(0);
      }
      break;
    }
    case 0x13: { /* CreateMutex(locked): out r1 */
      uint32_t handle = console_handle_new(CONSOLE_MUTEX, 0, NULL);
      if (handle && CTR_R(1)) console_acquire(console_handle_get(handle), console_self);
      CTR_R(1) = handle;
      break;
    }
    case 0x14: { /* ReleaseMutex(mutex) */
      struct console_object *o = ctr_object(CTR_R(0), CONSOLE_MUTEX);
      if (o == NULL) r = CTR_INVALID_HANDLE;
      else if (o->value != (uint64_t)console_self + 1) r = CTR_NOT_OWNER;
      else if (--o->count == 0) {
        o->value = 0;
        console_schedule(0);
      }
      break;
    }
    case 0x15: { /* CreateSemaphore(initial, maximum): out r1 */
      uint32_t handle = console_handle_new(CONSOLE_SEMAPHORE, 0, NULL);
      if (handle) {
        console_handle_get(handle)->count = CTR_R(1);
        console_handle_get(handle)->limit = CTR_R(2);
      }
      CTR_R(1) = handle;
      break;
    }
    case 0x16: { /* ReleaseSemaphore(semaphore, count): out r1 the count before */
      struct console_object *o = ctr_object(CTR_R(1), CONSOLE_SEMAPHORE);
      if (o == NULL) r = CTR_INVALID_HANDLE;
      else if (o->count + CTR_R(2) > o->limit) r = CTR_OUT_OF_RANGE;
      else {
        CTR_R(1) = o->count;
        o->count += CTR_R(2);
        console_schedule(0);
      }
      break;
    }
    case 0x17: { /* CreateEvent(reset): out r1. A pulse (2) is taken as one-shot. */
      uint32_t handle = console_handle_new(CONSOLE_EVENT, 0, NULL);
      if (handle) console_handle_get(handle)->limit = CTR_R(1) == 1;
      CTR_R(1) = handle;
      break;
    }
    case 0x18: case 0x19: { /* SignalEvent, ClearEvent */
      struct console_object *o = ctr_object(CTR_R(0), CONSOLE_EVENT);
      if (o == NULL) r = CTR_INVALID_HANDLE;
      else {
        o->count = s->svc == 0x18;
        if (o->count) console_schedule(0);
      }
      break;
    }
    case 0x21: CTR_R(1) = console_handle_new(CONSOLE_OTHER, 0, NULL); break; /* CreateAddressArbiter */
    case 0x22: { /* ArbitrateAddress(arbiter, address, type, value, timeout low, high) */
      uint32_t address = CTR_R(1), type = CTR_R(2);
      int32_t value = (int32_t)CTR_R(3), *word = (int32_t *)(s->mem + address);
      int64_t timeout = type >= 3 ? ctr_timeout(CTR_R(4), CTR_R(5)) : -1;
      if (type == 0) {
        console_signal_address(address, value);
        console_schedule(0);
      } else if (type <= 4) {
        if (*word < value) {
          if (type == 2 || type == 4) (*word)--;
          if (console_wait_address(address, timeout) < 0) r = CTR_TIMEOUT;
        }
      } else {
        console_unserved("svc ArbitrateAddress type", type);
        r = CTR_NOT_IMPLEMENTED;
      }
      break;
    }
    case 0x23: if (!console_handle_close(CTR_R(0))) r = CTR_INVALID_HANDLE; break; /* CloseHandle */
    case 0x24: { /* WaitSynchronization1(handle, _, timeout low, high) */
      uint32_t handle = CTR_R(0);
      int index = console_wait_objects(&handle, 1, 0, ctr_timeout(CTR_R(2), CTR_R(3)));
      r = index == -2 ? CTR_INVALID_HANDLE : index < 0 ? CTR_TIMEOUT : CTR_OK;
      break;
    }
    case 0x25: { /* WaitSynchronizationN(timeout low, handles, count, all, timeout high): out r1 the index */
      int count = (int)CTR_R(2);
      if (count < 0 || count > CONSOLE_WAIT_HANDLES) {
        r = CTR_OUT_OF_RANGE;
        break;
      }
      uint32_t handles[CONSOLE_WAIT_HANDLES];
      memcpy(handles, s->mem + CTR_R(1), (size_t)count * 4);
      int index = console_wait_objects(handles, count, CTR_R(3) != 0, ctr_timeout(CTR_R(0), CTR_R(4)));
      r = index == -2 ? CTR_INVALID_HANDLE : index < 0 ? CTR_TIMEOUT : CTR_OK;
      if (index >= 0) CTR_R(1) = (uint32_t)index;
      break;
    }
    case 0x28: { /* GetSystemTick: the 3DS's 268 MHz counter, from the host's monotonic clock */
      struct timespec t;
      clock_gettime(CLOCK_MONOTONIC, &t);
      uint64_t ticks = (uint64_t)t.tv_sec * 268111856u + (uint64_t)t.tv_nsec * 268111856u / 1000000000u;
      CTR_R(0) = (uint32_t)ticks;
      CTR_R(1) = (uint32_t)(ticks >> 32);
      return;
    }
    case 0x2D: { /* ConnectToPort(out handle, name): a session to the port's service */
      char name[13] = {0};
      strncpy(name, (const char *)(s->mem + CTR_R(1)), 12);
      uint32_t handle = console_handle_new(CONSOLE_SESSION, 0, console_service_lookup(name));
      CTR_R(1) = handle;
      if (handle == 0) r = CTR_NOT_IMPLEMENTED;
      break;
    }
    case 0x32: r = ctr_request(s, CTR_R(0)); break; /* SendSyncRequest */
    case 0x3C: fprintf(stderr, "atlas: the title called Break(%u)\n", CTR_R(0)); abort();
    case 0x3D: fwrite(s->mem + CTR_R(0), 1, CTR_R(1), stderr); break; /* OutputDebugString */
    default:
      console_unserved("svc", s->svc);
      r = CTR_NOT_IMPLEMENTED;
  }
  CTR_R(0) = r;
}
