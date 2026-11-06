import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { RUNTIME_HEADER } from "../../../src/tools/vex/index.js";

const KERNEL = join(dirname(RUNTIME_HEADER), "console", "kernel.inc");
const DEVICES = join(dirname(RUNTIME_HEADER), "console", "devices.inc");

// Registers in the hardware window, as a translation reaches them (LOAD and STORE): a registered device serves its
// range (offsets from its start, sizes as accessed); the rest of the window acts as memory and is logged; memory
// outside the window is untouched by either.
const DEVICE_HARNESS = `
#include "atlas_lift.h"
#include "${KERNEL}"
#include "${DEVICES}"
#include <assert.h>
static uint64_t last_offset, last_value; static unsigned last_size;
static uint64_t status(atlas_state *s, uint32_t offset, unsigned size) { (void)s; return 0x80 | offset | size << 8; }
static void put(atlas_state *s, uint32_t offset, unsigned size, uint64_t v) {
  (void)s; last_offset = offset; last_size = size; last_value = v;
}
int main(void) {
  static uint8_t memory[0x2000];
  atlas_state st = {0}; atlas_state *s = &st; s->mem = memory;
  console_device_register(0x1000, 0x1010, status, put);
  STORE16(0x1004, 0xBEEF);
  assert(last_offset == 4 && last_size == 2 && last_value == 0xBEEF && memory[0x1004] == 0);
  assert(LOAD8(0x1008) == (0x80 | 8 | 1 << 8) % 256 && LOAD32(0x100C) == (0x80 | 0xC | 4 << 8));
  STORE32(0x1800, 0x12345678); assert(LOAD32(0x1800) == 0x12345678); /* in the window, no device: memory */
  STORE32(0x0100, 7); assert(LOAD32(0x0100) == 7 && memory[0x0100] == 7); /* outside: plain memory */
  console_unserved_write();
  return 0;
}
`;

// The generic core alone, in a C harness: handles, the service registry, the unserved log.
const HARNESS = `
#include "atlas_lift.h"
#include "${KERNEL}"
#include <assert.h>
static void echo(atlas_state *s, uint8_t *command, struct console_object *session) { (void)s; (void)session; command[0]++; }
int main(void) {
  uint32_t a = console_handle_new(CONSOLE_EVENT, 7, NULL), b = console_handle_new(CONSOLE_MUTEX, 0, NULL);
  assert(a >= CONSOLE_HANDLE_BASE && b != a);
  assert(console_handle_get(a)->value == 7 && console_handle_get(0) == NULL && console_handle_get(1) == NULL);
  assert(console_handle_close(a) && !console_handle_close(a) && console_handle_get(a) == NULL);
  assert(console_handle_new(CONSOLE_PORT, 0, NULL) == a); /* a closed slot is reused */

  console_service_register("echo", echo);
  const struct console_service *e = console_service_lookup("echo"), *u = console_service_lookup("gsp::Gpu");
  assert(e->handler == echo && u != NULL && u->handler == NULL && console_service_lookup("gsp::Gpu") == u);
  uint8_t command[4] = {1};
  e->handler(NULL, command, NULL);
  assert(command[0] == 2);

  console_unserved("svc", 0x2d);
  for (int k = 0; k < 3; k++) console_unserved("gsp::Gpu", 0x10003);
  console_unserved_write();
  return 0;
}
`;

describe("console kernel core", () => {
  it("sends accesses in the hardware window to the devices, and logs the registers nothing serves", () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-console-"));
    writeFileSync(join(dir, "harness.c"), DEVICE_HARNESS);
    execFileSync(
      "gcc",
      [
        "-O1",
        "-w",
        "-DATLAS_DEVICE_LOW=0x1000",
        "-DATLAS_DEVICE_HIGH=0x2000",
        "-I",
        dirname(RUNTIME_HEADER),
        "harness.c",
      ],
      { cwd: dir },
    );
    const log = join(dir, "unserved.txt");
    execFileSync(join(dir, "a.out"), { env: { ...process.env, ATLAS_UNSERVED: log } });
    expect(readFileSync(log, "utf8")).toBe("1 device write 0x1800\n1 device read 0x1800\n");
  });

  it("gives and closes handles, finds services, and logs what is unserved, most asked first", () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-console-"));
    writeFileSync(join(dir, "harness.c"), HARNESS);
    execFileSync("gcc", ["-O1", "-w", "-I", dirname(RUNTIME_HEADER), "harness.c", "-o", "harness"], { cwd: dir });
    const log = join(dir, "unserved.txt");
    execFileSync(join(dir, "harness"), { env: { ...process.env, ATLAS_UNSERVED: log } });
    expect(readFileSync(log, "utf8")).toBe("3 gsp::Gpu 0x10003\n1 svc 0x2d\n");
  });
});
