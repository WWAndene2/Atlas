import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { locateAngr } from "../../../src/tools/angr/index.js";
import { crosslinkProgram, liftFunctions } from "../../../src/tools/vex/index.js";

function angr(): string | undefined {
  try {
    return locateAngr();
  } catch {
    return undefined;
  }
}
const python = angr();

// Whether clang can build a freestanding 32-bit ARM Linux program here (its own ARM backend and lld).
function armClang(): boolean {
  const dir = mkdtempSync(join(tmpdir(), "atlas-crosslink-probe-"));
  writeFileSync(join(dir, "p.c"), "void _start(void){for(;;);}");
  const r = spawnSync("clang", [...ARM_FLAGS, "p.c", "-o", "p"], { cwd: dir });
  return r.status === 0;
}
const ARM_FLAGS = ["--target=armv7a-linux-gnueabihf", "-O2", "-ffreestanding", "-nostdlib", "-static", "-fuse-ld=lld"];

// A freestanding ARM program: its own _start and system calls (ARM EABI: number in r7, svc 0). It checks what the
// emulated system calls return (an error as -errno, mmap2 with MAP_FIXED, clock_gettime64's 64-bit fields), prints
// its last argument and a computed sum, and exits 7 if every check held.
const PROGRAM = `
static long sys(long n, long a, long b, long c, long d, long e, long f) {
  register long r7 __asm__("r7") = n; register long r0 __asm__("r0") = a; register long r1 __asm__("r1") = b;
  register long r2 __asm__("r2") = c; register long r3 __asm__("r3") = d; register long r4 __asm__("r4") = e;
  register long r5 __asm__("r5") = f;
  __asm__ volatile("svc 0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5) : "memory");
  return r0;
}
static int len(const char *s) { int n = 0; while (s[n]) n++; return n; }
void _start_c(long *sp) {
  int argc = (int)sp[0]; char **argv = (char **)(sp + 1);
  int ok = sys(3, 99, 0, 1, 0, 0, 0) == -9;                                  /* read, closed fd: -EBADF */
  long m = sys(192, 0x20400000, 4096, 3, 0x32, -1, 0);                       /* mmap2 MAP_FIXED|PRIVATE|ANON */
  ok &= m == 0x20400000 && *(volatile int *)m == 0;
  ok &= sys(192, 0, 0, 3, 0x22, -1, 0) == -22;                               /* length 0: -EINVAL */
  long long ts[2] = {0, -1};
  ok &= sys(403, 0, (long)ts, 0, 0, 0, 0) == 0 && ts[0] > 1600000000 && ts[1] >= 0 && ts[1] < 1000000000;
  int sum = 0; for (int i = 1; i <= 100; i++) sum += i;
  char buf[16]; int k = 15; buf[k] = 0; do { buf[--k] = '0' + sum % 10; sum /= 10; } while (sum);
  sys(4, 1, (long)"hello ", 6, 0, 0, 0);
  sys(4, 1, (long)argv[argc - 1], len(argv[argc - 1]), 0, 0, 0);
  sys(4, 1, (long)" ", 1, 0, 0, 0); sys(4, 1, (long)(buf + k), len(buf + k), 0, 0, 0); sys(4, 1, (long)"\\n", 1, 0, 0, 0);
  sys(1, ok ? 7 : 1, 0, 0, 0, 0, 0);
}
__attribute__((naked)) void _start(void) { __asm__("mov r0, sp\\n bl _start_c\\n"); }
`;

// The program's functions as the graph has them (even address, code bytes), from its symbol table.
const FUNCTIONS = `
import cle, json, sys
o = cle.Loader(sys.argv[1], auto_load_libs=False).main_object
print(json.dumps([{"address": s.rebased_addr & ~1, "code": o.memory.load(s.relative_addr & ~1, s.size).hex()}
                  for s in o.symbols if s.is_function and s.size]))
`;

describe.runIf(python !== undefined && armClang())("crosslinkProgram", () => {
  for (const mode of ["arm", "thumb"]) {
    it(`runs a 32-bit ARM program (${mode} code) on this host, its system calls emulated`, async () => {
      const dir = mkdtempSync(join(tmpdir(), "atlas-crosslink-test-"));
      writeFileSync(join(dir, "p.c"), PROGRAM);
      execFileSync("clang", [...ARM_FLAGS, `-m${mode}`, "p.c", "-o", "p"], { cwd: dir });
      writeFileSync(join(dir, "functions.py"), FUNCTIONS);
      const functions = JSON.parse(
        execFileSync(python as string, ["-I", join(dir, "functions.py"), join(dir, "p")], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        }),
      ) as { address: number; code: string }[];
      expect(functions.length).toBeGreaterThanOrEqual(2);
      // The Thumb state is not passed: lift.py takes it from angr's CFG, as for a function from the graph.
      const lifted = await liftFunctions(python as string, "arm-v7", functions, join(dir, "p"));
      expect(lifted.filter((l) => "unsupported" in l)).toEqual([]);
      writeFileSync(
        join(dir, "lifted.c"),
        `#include "atlas_lift.h"\n${lifted.map((l) => ("c" in l ? l.c : "")).join("\n")}`,
      );
      const outcome = await crosslinkProgram(python as string, {
        arch: "ARMEL",
        endness: "Iend_LE",
        binary: join(dir, "p"),
        lifted: [join(dir, "lifted.c")],
        translated: functions.map((f) => f.address),
        out: join(dir, "program"),
        base: 0,
      });
      // An argument with a quote and a backslash reaches the guest intact.
      const run = spawnSync(outcome.executable, ["first", 'it\'s "x"\\'], { encoding: "utf8" });
      expect(run.stdout).toBe('hello it\'s "x"\\ 5050\n');
      expect(run.status).toBe(7);
    }, 300_000);
  }
});
