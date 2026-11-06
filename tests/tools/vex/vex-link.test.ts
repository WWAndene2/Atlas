import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { locateAngr } from "../../../src/tools/angr/index.js";
import {
  a64linkProgram,
  crosslinkProgram,
  liftFunctions,
  linkProgram,
  winlinkProgram,
} from "../../../src/tools/vex/index.js";

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

function has(tool: string): boolean {
  return spawnSync("sh", ["-c", `command -v ${tool}`]).status === 0;
}

// A Windows x64 program (MinGW, msvcrt): Windows' printf sizes (l is 32 bits, I64 64), setjmp and longjmp across
// frames, files, the environment, atexit and the exit code, all through the services winlink.py links in.
const WINDOWS_PROGRAM = `
#include <math.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static jmp_buf env;
static void deep(int n) { if (n == 0) longjmp(env, 42); deep(n - 1); }
static void bye(void) { fputs("bye\\n", stdout); }
int main(int argc, char **argv) {
  atexit(bye);
  int got = setjmp(env);
  if (got == 0) deep(5);
  long l = -5; long long big = 1LL << 40;
  fprintf(stdout, "%s|%d|%ld|%I64d|%lld|%5.2f|%x|%c|%%\\n", argv[argc - 1], got, l, big, big, pow(2.0, 0.5), 255u, 'z');
  FILE *f = fopen(argv[1], "wb");
  fwrite("abc\\n", 1, 4, f); fclose(f);
  char buf[16] = {0};
  f = fopen(argv[1], "rb"); fseek(f, 1, SEEK_SET);
  fgets(buf, sizeof buf, f); long at = ftell(f); fclose(f); remove(argv[1]);
  fprintf(stdout, "%s%ld %s\\n", buf, at, getenv("ATLAS_WIN_TEST") ? getenv("ATLAS_WIN_TEST") : "-");
  return strlen(argv[argc - 1]) == 5 ? 3 : 1;
}
`;

// The program's functions from its COFF symbol table (the answer key; the graph supplies them in use), each up to
// the next: hand-written ones like ___chkstk_ms have no .pdata entry.
const PE_FUNCTIONS = `
import json, subprocess, sys
import pefile
pe = pefile.PE(sys.argv[1])
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Characteristics & 0x20000000)
lo, hi = base + text.VirtualAddress, base + text.VirtualAddress + text.Misc_VirtualSize
nm = subprocess.run([sys.argv[2], sys.argv[1]], capture_output=True, text=True, check=True).stdout
starts = sorted({int(l.split()[0], 16) for l in nm.splitlines() if len(l.split()) == 3 and l.split()[1] in "Tt"})
starts = [a for a in starts if lo <= a < hi]
print(json.dumps([{"address": a, "code": pe.get_data(a - base, b - a).hex()} for a, b in zip(starts, starts[1:] + [hi])]))
`;

describe.runIf(python !== undefined && has("x86_64-w64-mingw32-gcc") && has("x86_64-w64-mingw32-nm"))(
  "winlinkProgram",
  () => {
    it("runs a Windows x64 program on this Linux host, its C library and kernel32 served", async () => {
      const dir = mkdtempSync(join(tmpdir(), "atlas-winlink-test-"));
      writeFileSync(join(dir, "p.c"), WINDOWS_PROGRAM);
      execFileSync("x86_64-w64-mingw32-gcc", ["-O2", "p.c", "-o", "p.exe"], { cwd: dir });
      writeFileSync(join(dir, "functions.py"), PE_FUNCTIONS);
      const functions = JSON.parse(
        execFileSync(python as string, ["-I", join(dir, "functions.py"), join(dir, "p.exe"), "x86_64-w64-mingw32-nm"], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        }),
      ) as { address: number; code: string }[];
      const lifted = await liftFunctions(python as string, "x86_64", functions, join(dir, "p.exe"));
      expect(lifted.filter((l) => "unsupported" in l)).toEqual([]);
      writeFileSync(
        join(dir, "lifted.c"),
        `#include "atlas_lift.h"\n${lifted.map((l) => ("c" in l ? l.c : "")).join("\n")}`,
      );
      const outcome = await winlinkProgram(python as string, {
        binary: join(dir, "p.exe"),
        lifted: [join(dir, "lifted.c")],
        translated: lifted.filter((l) => "c" in l).map((l) => Number(l.address)),
        out: join(dir, "program"),
      });
      expect(outcome.unserved).toEqual([]);
      const run = spawnSync(outcome.executable, [join(dir, "x.tmp"), "hello"], {
        encoding: "utf8",
        env: { ...process.env, ATLAS_WIN_TEST: "env" },
      });
      expect(run.stdout).toBe("hello|42|-5|1099511627776|1099511627776| 1.41|ff|z|%\nbc\n4 env\nbye\n");
      expect(run.status).toBe(3);
    }, 600_000);
  },
);

// An AArch64 Linux program linked against the C library (as an Android app's native executable is): mixed
// integer and floating-point arguments, a variadic call with more arguments than registers, setjmp and longjmp
// across frames, files, the environment, a stack-protected function (AArch64's global __stack_chk_guard) and the
// exit code, all through the host's C library.
const A64_PROGRAM = `
#include <math.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static jmp_buf env;
static void deep(int n) { if (n == 0) longjmp(env, 42); deep(n - 1); }
static int guarded(const char *s) { char buf[64]; strncpy(buf, s, sizeof buf - 1); buf[63] = 0; return (int)strlen(buf); }
int main(int argc, char **argv) {
  int got = setjmp(env);
  if (got == 0) deep(5);
  printf("%s|%d|%ld|%.3f|%d|%d|%d|%d|%d|%d|%.1f|%.1f\\n", argv[argc - 1], got, -5L, pow(2.0, 0.5), 1, 2, 3, 4, 5, 6,
         ldexp(1.5, 3), frexp(8.0, &got));
  FILE *f = fopen(argv[1], "w"); fprintf(f, "abc %d\\n", got); fclose(f);
  char line[32] = {0};
  f = fopen(argv[1], "r"); fgets(line, sizeof line, f); fclose(f); remove(argv[1]);
  printf("%s%s %d\\n", line, getenv("ATLAS_A64_TEST") ? getenv("ATLAS_A64_TEST") : "-", guarded(argv[0]) > 0);
  return 3;
}
`;

const ELF_FUNCTIONS = `
import cle, json, sys
o = cle.Loader(sys.argv[1], auto_load_libs=False, main_opts={"base_addr": 0}).main_object
print(json.dumps([{"address": s.relative_addr, "code": o.memory.load(s.relative_addr, s.size).hex()}
                  for s in o.symbols if s.is_function and s.size and not s.is_import]))
`;

describe.runIf(python !== undefined && has("aarch64-linux-gnu-gcc"))("a64linkProgram", () => {
  it("runs an AArch64 Linux program on this x86-64 host, its imports served by the host's C library", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-a64link-test-"));
    writeFileSync(join(dir, "p.c"), A64_PROGRAM);
    execFileSync("aarch64-linux-gnu-gcc", ["-O2", "-fstack-protector-all", "p.c", "-o", "p", "-lm"], { cwd: dir });
    writeFileSync(join(dir, "functions.py"), ELF_FUNCTIONS);
    const functions = JSON.parse(
      execFileSync(python as string, ["-I", join(dir, "functions.py"), join(dir, "p")], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }),
    ) as { address: number; code: string }[];
    // A position-independent image, mapped at 0x10000000 as atlas lift --link maps one (linkBase).
    const base = 0x10000000;
    const lifted = await liftFunctions(python as string, "arm64", functions, join(dir, "p"), base);
    expect(lifted.filter((l) => "unsupported" in l)).toEqual([]);
    const c = lifted.map((l) => ("c" in l ? l.c : "")).join("\n");
    writeFileSync(join(dir, "lifted.c"), `#include "atlas_lift.h"\n${c}`);
    const outcome = await a64linkProgram(python as string, {
      binary: join(dir, "p"),
      lifted: [join(dir, "lifted.c")],
      translated: lifted.filter((l) => "c" in l).map((l) => Number(l.address)),
      out: join(dir, "program"),
      base,
    });
    expect(outcome.own).toEqual(["__stack_chk_guard"]);
    const run = spawnSync(outcome.executable, [join(dir, "x.tmp"), "hello"], {
      encoding: "utf8",
      env: { ...process.env, ATLAS_A64_TEST: "env" },
    });
    expect(run.stdout).toBe("hello|42|-5|1.414|1|2|3|4|5|6|12.0|0.5\nabc 4\nenv 1\n");
    expect(run.status).toBe(3);
  }, 600_000);
});

// An x86-64 Linux program handing its own functions to the C library (qsort, bsearch, atexit): link.py maps the
// original's code at its own addresses, executable, so the library calls the function's original machine code, which
// runs as it is on an x86-64 host.
const CALLBACK_PROGRAM = `
#include <stdio.h>
#include <stdlib.h>
static int descending(const void *a, const void *b) { return *(const int *)b - *(const int *)a; }
static void bye(void) { puts("bye"); }
int main(void) {
  atexit(bye);
  int v[] = {5, 1, 9, 3, 7, 2, 8};
  qsort(v, 7, sizeof v[0], descending);
  for (int i = 0; i < 7; i++) printf("%d ", v[i]);
  int key = 3;
  int *found = bsearch(&key, v, 7, sizeof v[0], descending);
  printf("| %d at %d\\n", found ? *found : -1, found ? (int)(found - v) : -1);
  return 0;
}
`;

describe.runIf(python !== undefined)("linkProgram", () => {
  it("lets the host's C library call a function of the program it was handed (qsort, bsearch, atexit)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-callback-test-"));
    writeFileSync(join(dir, "p.c"), CALLBACK_PROGRAM);
    execFileSync("gcc", ["-O1", "-fcf-protection=none", "p.c", "-o", "p"], { cwd: dir });
    writeFileSync(join(dir, "functions.py"), ELF_FUNCTIONS);
    const functions = JSON.parse(
      execFileSync(python as string, ["-I", join(dir, "functions.py"), join(dir, "p")], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }),
    ) as { address: number; code: string }[];
    const base = 0x10000000; // a position-independent image, mapped where atlas lift --link maps one
    const lifted = await liftFunctions(python as string, "x86_64", functions, join(dir, "p"), base);
    expect(lifted.filter((l) => "unsupported" in l)).toEqual([]);
    const c = lifted.map((l) => ("c" in l ? l.c : "")).join("\n");
    writeFileSync(join(dir, "lifted.c"), `#include "atlas_lift.h"\n${c}`);
    const outcome = await linkProgram(python as string, {
      binary: join(dir, "p"),
      lifted: [join(dir, "lifted.c")],
      translated: lifted.filter((l) => "c" in l).map((l) => Number(l.address)),
      out: join(dir, "program"),
      rewrites: [],
      functions: {},
      base,
    });
    const run = spawnSync(outcome.executable, [], { encoding: "utf8" });
    expect(run.stdout).toBe("9 8 7 5 3 2 1 | 3 at 4\nbye\n");
    expect(run.status).toBe(0);
  }, 600_000);
});

describe.runIf(python !== undefined && has("aarch64-linux-gnu-gcc"))("a64linkProgram callbacks", () => {
  it("lets the host's C library call an AArch64 function it was handed (qsort, bsearch, atexit)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-a64-callback-test-"));
    writeFileSync(join(dir, "p.c"), CALLBACK_PROGRAM);
    execFileSync("aarch64-linux-gnu-gcc", ["-O1", "p.c", "-o", "p"], { cwd: dir });
    writeFileSync(join(dir, "functions.py"), ELF_FUNCTIONS);
    const functions = JSON.parse(
      execFileSync(python as string, ["-I", join(dir, "functions.py"), join(dir, "p")], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }),
    ) as { address: number; code: string }[];
    const base = 0x10000000;
    const lifted = await liftFunctions(python as string, "arm64", functions, join(dir, "p"), base);
    expect(lifted.filter((l) => "unsupported" in l)).toEqual([]);
    const c = lifted.map((l) => ("c" in l ? l.c : "")).join("\n");
    writeFileSync(join(dir, "lifted.c"), `#include "atlas_lift.h"\n${c}`);
    const outcome = await a64linkProgram(python as string, {
      binary: join(dir, "p"),
      lifted: [join(dir, "lifted.c")],
      translated: lifted.filter((l) => "c" in l).map((l) => Number(l.address)),
      out: join(dir, "program"),
      base,
    });
    const run = spawnSync(outcome.executable, [], { encoding: "utf8" });
    expect(run.stdout).toBe("9 8 7 5 3 2 1 | 3 at 4\nbye\n");
    expect(run.status).toBe(0);
  }, 600_000);
});

// An AArch64 program installing its own signal handler with sigaction, then raising the signal: the host delivers
// it to the translated handler. The old action handed back is the program's own handler again.
const SIGNAL_PROGRAM = `
#include <signal.h>
#include <stdio.h>
#include <string.h>
static volatile sig_atomic_t got;
static void on_usr1(int sig) { got = sig; }
int main(void) {
  struct sigaction sa, old;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_usr1;
  sigaction(SIGUSR1, &sa, 0);
  raise(SIGUSR1);
  sigaction(SIGUSR1, &sa, &old);
  printf("got %d, old handler is ours: %d\\n", (int)got, old.sa_handler == on_usr1);
  return 0;
}
`;

describe.runIf(python !== undefined && has("aarch64-linux-gnu-gcc"))("a64linkProgram signals", () => {
  it("delivers a signal to an AArch64 program's own handler installed with sigaction", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-a64-signal-test-"));
    writeFileSync(join(dir, "p.c"), SIGNAL_PROGRAM);
    execFileSync("aarch64-linux-gnu-gcc", ["-O1", "p.c", "-o", "p"], { cwd: dir });
    writeFileSync(join(dir, "functions.py"), ELF_FUNCTIONS);
    const functions = JSON.parse(
      execFileSync(python as string, ["-I", join(dir, "functions.py"), join(dir, "p")], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }),
    ) as { address: number; code: string }[];
    const base = 0x10000000;
    const lifted = await liftFunctions(python as string, "arm64", functions, join(dir, "p"), base);
    expect(lifted.filter((l) => "unsupported" in l)).toEqual([]);
    const c = lifted.map((l) => ("c" in l ? l.c : "")).join("\n");
    writeFileSync(join(dir, "lifted.c"), `#include "atlas_lift.h"\n${c}`);
    const outcome = await a64linkProgram(python as string, {
      binary: join(dir, "p"),
      lifted: [join(dir, "lifted.c")],
      translated: lifted.filter((l) => "c" in l).map((l) => Number(l.address)),
      out: join(dir, "program"),
      base,
    });
    const run = spawnSync(outcome.executable, [], { encoding: "utf8" });
    expect(run.stdout).toBe("got 10, old handler is ours: 1\n");
    expect(run.status).toBe(0);
  }, 600_000);
});
