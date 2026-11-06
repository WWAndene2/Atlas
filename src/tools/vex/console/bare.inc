/* The profile of a machine with no operating system (after console/kernel.inc and console/devices.inc): the program
 * owns the machine, drives its hardware through registers (the devices window crosslink's request gives), and asks
 * no kernel for anything. What it does ask through svc is ARM semihosting (svc 0x123456 in ARM code: the operation
 * in r0, its argument in r1), the standard way a bare-metal program prints and stops under a debugger or QEMU:
 * SYS_WRITEC, SYS_WRITE0 and SYS_EXIT are served. Any other svc, or semihosting operation, is logged as unserved.
 * Included after crosslink defines BARE_R0 and BARE_R1 (the guest offsets of r0 and r1). */

#define BARE_SEMIHOSTING 0x123456u
#define BARE_EXIT_APPLICATION 0x20026u /* ADP_Stopped_ApplicationExit: a normal end */

static void bare_setup(atlas_state *s) {
  (void)s;
  atexit(console_unserved_write);
}

static void bare_syscall(atlas_state *s) {
  uint32_t op = REG(uint32_t, BARE_R0), argument = REG(uint32_t, BARE_R1);
  if (s->svc != BARE_SEMIHOSTING) {
    console_unserved("svc", s->svc);
    return;
  }
  switch (op) {
    case 0x03: fputc(s->mem[argument], stdout); break;                       /* SYS_WRITEC: a character */
    case 0x04: fputs((const char *)(s->mem + argument), stdout); break;     /* SYS_WRITE0: a string */
    case 0x18: fflush(stdout); exit(argument == BARE_EXIT_APPLICATION ? 0 : 1); /* SYS_EXIT(reason) */
    default: console_unserved("semihosting", op); REG(uint32_t, BARE_R0) = (uint32_t)-1;
  }
}
