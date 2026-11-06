import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { RUNTIME_HEADER } from "../../../src/tools/vex/index.js";

const KERNEL = join(dirname(RUNTIME_HEADER), "console", "kernel.inc");

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
  it("gives and closes handles, finds services, and logs what is unserved, most asked first", () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-console-"));
    writeFileSync(join(dir, "harness.c"), HARNESS);
    execFileSync("gcc", ["-O1", "-w", "-I", dirname(RUNTIME_HEADER), "harness.c", "-o", "harness"], { cwd: dir });
    const log = join(dir, "unserved.txt");
    execFileSync(join(dir, "harness"), { env: { ...process.env, ATLAS_UNSERVED: log } });
    expect(readFileSync(log, "utf8")).toBe("3 gsp::Gpu 0x10003\n1 svc 0x2d\n");
  });
});
