/* The 3DS profile of the console kernel (console/kernel.inc): Horizon's system calls, its IPC command format, and its
 * service registry, srv:. Included by crosslink.py's program when the request's profile is "ctr", after it defines
 * ctr_reg (the guest offsets of r0 to r4) and CTR_TLS_REG (TPIDRURO's).
 *
 * Horizon's convention: the call's number is the svc instruction's immediate (s->svc); arguments in r0 to r3 (r4
 * for a fifth), the result code in r0, outputs in r1 and up. A thread's command buffer is at its TLS + 0x80; a
 * request's header is (command << 16) | (normal words << 6) | translate words, and the reply is written over it.
 *
 * What is not served returns CTR_NOT_IMPLEMENTED and is logged (console_unserved): a title's needs are read from the
 * log, not guessed. Success is not faked, so a title that checks results takes its own error path rather than
 * running on with nothing behind it. One thread; waits return at once (nothing else can signal). */
#include <time.h>

#define CTR_R(n) REG(uint32_t, ctr_reg[n])
#define CTR_OK 0u
#define CTR_NOT_IMPLEMENTED 0xF8C007F4u /* Horizon's "not implemented" (level permanent, summary not supported) */
#define CTR_INVALID_HANDLE 0xD8E007F7u

/* The guest's memory, at the 3DS's own addresses (all mapped already: committing memory only hands out addresses). */
#define CTR_HEAP 0x08000000u
#define CTR_LINEAR 0x14000000u
#define CTR_STACK_TOP 0x10000000u
#define CTR_TLS 0x1FF82000u
static uint32_t ctr_heap_next = CTR_HEAP, ctr_linear_next = CTR_LINEAR;

static uint32_t *ctr_command(atlas_state *s) { return (uint32_t *)(s->mem + CTR_TLS + 0x80); }

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
}

static uint32_t ctr_new_handle(enum console_kind kind, uint64_t value) {
  return console_handle_new(kind, value, NULL);
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
    case 0x0A: break;   /* SleepThread: nothing else runs, so the sleep is over */
    case 0x13: CTR_R(1) = ctr_new_handle(CONSOLE_MUTEX, CTR_R(1)); break;          /* CreateMutex(locked) */
    case 0x14: break;                                                              /* ReleaseMutex */
    case 0x17: CTR_R(1) = ctr_new_handle(CONSOLE_EVENT, 0); break;                 /* CreateEvent */
    case 0x18: case 0x19: break;                                                   /* SignalEvent, ClearEvent */
    case 0x21: CTR_R(1) = ctr_new_handle(CONSOLE_OTHER, 0); break;                 /* CreateAddressArbiter */
    case 0x22: break;                                                              /* ArbitrateAddress */
    case 0x23: if (!console_handle_close(CTR_R(0))) r = CTR_INVALID_HANDLE; break; /* CloseHandle */
    case 0x24: break;                                                              /* WaitSynchronization1 */
    case 0x25: CTR_R(1) = 0; break;                                                /* WaitSynchronizationN: first */
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
