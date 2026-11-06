/* The console kernel's fourth entry point (after console/kernel.inc): memory accesses intercepted in a window of
 * addresses, for machines whose programs drive their hardware through registers (no operating system, or one that
 * leaves some devices to the program). Built with ATLAS_DEVICE_LOW and ATLAS_DEVICE_HIGH, the runtime
 * (atlas_lift.h) hands every access in the window to atlas_device_load and atlas_device_store here.
 *
 * A profile registers its devices: a range of registers and the functions that read and write them. An access no
 * device serves acts as plain memory (a register reads back what was written: what a program expects of a latch or
 * a scratch register) and is logged as unserved ("device read" or "device write", by address), so the registers a
 * program needs are read from the log, as its system calls are. */

typedef uint64_t (*console_device_read)(atlas_state *s, uint32_t offset, unsigned size);
typedef void (*console_device_write)(atlas_state *s, uint32_t offset, unsigned size, uint64_t value);
struct console_device {
  uint64_t low, high; /* [low, high) */
  console_device_read read;
  console_device_write write;
};

#define CONSOLE_DEVICES 64
static struct console_device console_devices[CONSOLE_DEVICES];
static int console_device_count;

static void console_device_register(uint64_t low, uint64_t high, console_device_read read,
                                    console_device_write write) {
  if (console_device_count < CONSOLE_DEVICES)
    console_devices[console_device_count++] = (struct console_device){low, high, read, write};
}

static const struct console_device *console_device_find(uint64_t a) {
  for (int k = 0; k < console_device_count; k++)
    if (a >= console_devices[k].low && a < console_devices[k].high) return &console_devices[k];
  return NULL;
}

uint64_t atlas_device_load(atlas_state *s, uint64_t a, unsigned size) {
  const struct console_device *d = console_device_find(a);
  if (d != NULL && d->read != NULL) return d->read(s, (uint32_t)(a - d->low), size);
  console_unserved("device read", (uint32_t)a);
  uint64_t v = 0;
  memcpy(&v, ATLAS_HOST(a), size); /* little-endian host: the low bytes, as the guest wrote them */
  return v;
}

void atlas_device_store(atlas_state *s, uint64_t a, unsigned size, uint64_t v) {
  const struct console_device *d = console_device_find(a);
  if (d != NULL && d->write != NULL) {
    d->write(s, (uint32_t)(a - d->low), size, v);
    return;
  }
  console_unserved("device write", (uint32_t)a);
  memcpy(ATLAS_HOST(a), &v, size);
}
