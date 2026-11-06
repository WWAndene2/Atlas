import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
      rmSync(join(dir, "p")); // the output does not need the original any more
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
  char name[L_tmpnam + 8]; memset(name, 'X', sizeof name); tmpnam(name); /* must stay within L_tmpnam */
  if (name[L_tmpnam] != 'X' || strlen(name) >= L_tmpnam) return 9;
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
      rmSync(join(dir, "p.exe")); // the output does not need the original any more
      const run = spawnSync(outcome.executable, [join(dir, "x.tmp"), "hello"], {
        encoding: "utf8",
        env: { ...process.env, ATLAS_WIN_TEST: "env" },
      });
      expect(run.stdout).toBe("hello|42|-5|1099511627776|1099511627776| 1.41|ff|z|%\nbc\n4 env\nbye\n");
      expect(run.status).toBe(3);
      // ATLAS_COVERAGE: the translated functions that ran, each one of the program's.
      const coverage = join(dir, "coverage.txt");
      spawnSync(outcome.executable, [join(dir, "x.tmp"), "hello"], {
        env: { ...process.env, ATLAS_COVERAGE: coverage },
      });
      const ran = readFileSync(coverage, "utf8")
        .trim()
        .split("\n")
        .map((a) => Number(a));
      expect(ran.length).toBeGreaterThan(1);
      expect(ran.every((a) => functions.some((f) => f.address === a))).toBe(true);
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
# One entry per address: a library lists its exports in both .symtab and .dynsym.
seen = {s.relative_addr: s for s in o.symbols if s.is_function and s.size and not s.is_import}
print(json.dumps([{"address": a, "code": o.memory.load(a, s.size).hex()} for a, s in sorted(seen.items())]))
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
    rmSync(join(dir, "p")); // the output does not need the original any more
    const run = spawnSync(outcome.executable, [join(dir, "x.tmp"), "hello"], {
      encoding: "utf8",
      env: { ...process.env, ATLAS_A64_TEST: "env" },
    });
    expect(run.stdout).toBe("hello|42|-5|1.414|1|2|3|4|5|6|12.0|0.5\nabc 4\nenv 1\n");
    expect(run.status).toBe(3);
    // ATLAS_COVERAGE: the translated functions that ran, each one of the program's.
    const coverage = join(dir, "coverage.txt");
    spawnSync(outcome.executable, [join(dir, "x.tmp"), "hello"], { env: { ...process.env, ATLAS_COVERAGE: coverage } });
    const ran = readFileSync(coverage, "utf8")
      .trim()
      .split("\n")
      .map((a) => Number(a));
    expect(ran.length).toBeGreaterThan(1);
    expect(ran.every((a) => functions.some((f) => f.address === a))).toBe(true);
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
    rmSync(join(dir, "p")); // the output does not need the original any more
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
    rmSync(join(dir, "p")); // the output does not need the original any more
    const run = spawnSync(outcome.executable, [], { encoding: "utf8" });
    expect(run.stdout).toBe("9 8 7 5 3 2 1 | 3 at 4\nbye\n");
    expect(run.status).toBe(0);
  }, 600_000);
});

// An AArch64 program installing its own signal handler with sigaction, then signal, raising the signal each time: the host delivers
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
  signal(SIGUSR2, on_usr1);
  raise(SIGUSR2);
  printf("got %d, previous is ours: %d\\n", (int)got, signal(SIGUSR2, SIG_DFL) == on_usr1);
  return 0;
}
`;

describe.runIf(python !== undefined && has("aarch64-linux-gnu-gcc"))("a64linkProgram signals", () => {
  it("delivers a signal to an AArch64 program's own handler installed with sigaction or signal", async () => {
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
    rmSync(join(dir, "p")); // the output does not need the original any more
    const run = spawnSync(outcome.executable, [], { encoding: "utf8" });
    expect(run.stdout).toBe("got 10, old handler is ours: 1\ngot 12, previous is ours: 1\n");
    expect(run.status).toBe(0);
  }, 600_000);
});

// An AArch64 shared library (as an Android app's native code is) linked for this host: a host shared library whose
// exports are the original's, called by a host program through dlopen.
const A64_LIBRARY = `
#include <stdio.h>
#include <stdlib.h>
int add(int a, int b) { return a + b; }
int counter = 41;                                               /* exported data */
const char version[] = "lib 1.0";
int bump(void) { return ++counter; }
int add3(int a, int b, int c) { return add(add(a, b), c); } /* one export calling another: through the PLT */
int (*pick)(int, int) = add;                                  /* a pointer to an export: a symbol relocation */
int through(int a, int b) { return pick(a, b); }
double scale(double x, int n) { return x * n; }
char *greet(const char *who) { char *s = malloc(64); snprintf(s, 64, "hello %s", who); return s; }
`;
const HOST_DRIVER = `
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
  void *lib = dlopen(argv[1], RTLD_NOW);
  if (!lib) { puts(dlerror()); return 1; }
  int (*add)(int, int) = (int (*)(int, int))dlsym(lib, "add");
  double (*scale)(double, int) = (double (*)(double, int))dlsym(lib, "scale");
  char *(*greet)(const char *) = (char *(*)(const char *))dlsym(lib, "greet");
  int (*add3)(int, int, int) = (int (*)(int, int, int))dlsym(lib, "add3");
  int (*through)(int, int) = (int (*)(int, int))dlsym(lib, "through");
  int (*bump)(void) = (int (*)(void))dlsym(lib, "bump");
  int *counter = (int *)dlsym(lib, "counter");
  const char *version = (const char *)dlsym(lib, "version");
  if (!counter || !version) { puts("no exported data"); return 2; }
  bump();
  printf("data %d %s\\n", *counter, version);
  char *g = greet("host");
  printf("%d %.2f %s %d %d\\n", add(40, 2), scale(1.25, 4), g, add3(1, 2, 3), through(5, 6));
  free(g);
  return 0;
}
`;

describe.runIf(python !== undefined && has("aarch64-linux-gnu-gcc"))("a64linkProgram libraries", () => {
  it("links an AArch64 shared library as a host library whose exports a host program calls", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-a64-library-test-"));
    writeFileSync(join(dir, "lib.c"), A64_LIBRARY);
    execFileSync("aarch64-linux-gnu-gcc", ["-O1", "-fPIC", "-shared", "lib.c", "-o", "lib.so"], { cwd: dir });
    writeFileSync(join(dir, "functions.py"), ELF_FUNCTIONS);
    const functions = JSON.parse(
      execFileSync(python as string, ["-I", join(dir, "functions.py"), join(dir, "lib.so")], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }),
    ) as { address: number; code: string }[];
    const base = 0x10000000;
    const lifted = await liftFunctions(python as string, "arm64", functions, join(dir, "lib.so"), base);
    expect(lifted.filter((l) => "unsupported" in l)).toEqual([]);
    const c = lifted.map((l) => ("c" in l ? l.c : "")).join("\n");
    writeFileSync(join(dir, "lifted.c"), `#include "atlas_lift.h"\n${c}`);
    const outcome = await a64linkProgram(python as string, {
      binary: join(dir, "lib.so"),
      lifted: [join(dir, "lifted.c")],
      translated: lifted.filter((l) => "c" in l).map((l) => Number(l.address)),
      out: join(dir, "host.so"),
      base,
    });
    writeFileSync(join(dir, "driver.c"), HOST_DRIVER);
    execFileSync("gcc", ["-O1", "driver.c", "-o", "driver", "-ldl"], { cwd: dir });
    rmSync(join(dir, "lib.so")); // the output does not need the original any more
    const run = spawnSync(join(dir, "driver"), [outcome.executable], { encoding: "utf8" });
    expect(run.stdout).toBe("data 42 lib 1.0\n42 5.00 hello host 6 11\n");
    expect(run.status).toBe(0);
  }, 600_000);
});

// An Android-style JNI library: native methods of a Java class, written against jni.h, which call back into the
// Java VM through the JNIEnv table (host function pointers). Built for AArch64, linked for this host and loaded by a
// real Java VM.
const JNI_LIBRARY = `
#include <jni.h>
#include <stdio.h>
JNIEXPORT jint JNICALL Java_Hello_add(JNIEnv *env, jclass cls, jint a, jint b) { return a + b; }
JNIEXPORT jstring JNICALL Java_Hello_greet(JNIEnv *env, jclass cls, jstring who) {
  const char *name = (*env)->GetStringUTFChars(env, who, 0);
  char text[64];
  snprintf(text, sizeof text, "hello %s from AArch64", name);
  (*env)->ReleaseStringUTFChars(env, who, name);
  return (*env)->NewStringUTF(env, text);
}
`;
const JAVA_CLASS = `
public class Hello {
  static native int add(int a, int b);
  static native String greet(String who);
  public static void main(String[] args) {
    System.load(args[0]);
    System.out.println(add(40, 2) + " " + greet("java"));
  }
}
`;

function javaHome(): string | undefined {
  const r = spawnSync("sh", ["-c", "dirname $(dirname $(readlink -f $(command -v javac)))"], { encoding: "utf8" });
  const home = r.stdout.trim();
  return r.status === 0 && home !== "" && existsSync(join(home, "include", "jni.h")) ? home : undefined;
}

describe.runIf(python !== undefined && has("aarch64-linux-gnu-gcc") && javaHome() !== undefined)("JNI", () => {
  it("runs an AArch64 JNI library's native methods in a host Java VM, calling back through JNIEnv", async () => {
    const home = javaHome() as string;
    const dir = mkdtempSync(join(tmpdir(), "atlas-jni-test-"));
    writeFileSync(join(dir, "hello.c"), JNI_LIBRARY);
    execFileSync(
      "aarch64-linux-gnu-gcc",
      [
        "-O1",
        "-fPIC",
        "-shared",
        "-I",
        join(home, "include"),
        "-I",
        join(home, "include", "linux"),
        "hello.c",
        "-o",
        "libhello.so",
      ],
      { cwd: dir },
    );
    writeFileSync(join(dir, "functions.py"), ELF_FUNCTIONS);
    const functions = JSON.parse(
      execFileSync(python as string, ["-I", join(dir, "functions.py"), join(dir, "libhello.so")], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }),
    ) as { address: number; code: string }[];
    const base = 0x10000000;
    const lifted = await liftFunctions(python as string, "arm64", functions, join(dir, "libhello.so"), base);
    expect(lifted.filter((l) => "unsupported" in l)).toEqual([]);
    const c = lifted.map((l) => ("c" in l ? l.c : "")).join("\n");
    writeFileSync(join(dir, "lifted.c"), `#include "atlas_lift.h"\n${c}`);
    const outcome = await a64linkProgram(python as string, {
      binary: join(dir, "libhello.so"),
      lifted: [join(dir, "lifted.c")],
      translated: lifted.filter((l) => "c" in l).map((l) => Number(l.address)),
      out: join(dir, "host-libhello.so"),
      base,
    });
    writeFileSync(join(dir, "Hello.java"), JAVA_CLASS);
    execFileSync("javac", ["Hello.java"], { cwd: dir, stdio: "ignore" });
    const run = spawnSync("java", ["-cp", dir, "Hello", outcome.executable], { encoding: "utf8" });
    expect(run.stdout).toBe("42 hello java from AArch64\n");
    expect(run.status).toBe(0);
  }, 600_000);
});

describe.runIf(python !== undefined && has("aarch64-linux-gnu-gcc"))("a64linkProgram wrong addresses", () => {
  it("reports a call to an address no loaded module holds instead of jumping there", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-a64-wrong-test-"));
    writeFileSync(
      join(dir, "p.c"),
      '#include <stdio.h>\nint main(void) { int (*volatile f)(void) = (int (*)(void))0x7ff000001234; puts("before"); fflush(stdout); return f(); }\n',
    );
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
    expect(run.stdout).toBe("before\n");
    expect(run.stderr).toContain("atlas: a call to 0x7ff000001234, in no loaded module");
    expect(run.status).not.toBe(0);
  }, 600_000);
});

// Several host threads calling into an AArch64 library at once: each needs a guest state of its own.
const THREAD_LIBRARY = `
long work(long seed) { long h = seed; for (long i = 0; i < 2000000; i++) h = h * 6364136223846793005L + 1442695040888963407L; return h; }
`;
const THREAD_DRIVER = `
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
static long (*work)(long);
static void *run(void *seed) { return (void *)work((long)seed); }
int main(int argc, char **argv) {
  void *lib = dlopen(argv[1], RTLD_NOW);
  if (!lib) { puts(dlerror()); return 1; }
  work = (long (*)(long))dlsym(lib, "work");
  long alone[4];
  for (long k = 0; k < 4; k++) alone[k] = work(k + 1);
  pthread_t t[4];
  for (long k = 0; k < 4; k++) pthread_create(&t[k], 0, run, (void *)(k + 1));
  int same = 1;
  for (long k = 0; k < 4; k++) { void *r; pthread_join(t[k], &r); same &= (long)r == alone[k]; }
  printf("threads agree: %d\\n", same);
  return 0;
}
`;

describe.runIf(python !== undefined && has("aarch64-linux-gnu-gcc"))("a64linkProgram threads", () => {
  it("gives each host thread calling into an AArch64 library a guest state of its own", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-a64-threads-test-"));
    writeFileSync(join(dir, "lib.c"), THREAD_LIBRARY);
    execFileSync("aarch64-linux-gnu-gcc", ["-O1", "-fPIC", "-shared", "lib.c", "-o", "lib.so"], { cwd: dir });
    writeFileSync(join(dir, "functions.py"), ELF_FUNCTIONS);
    const functions = JSON.parse(
      execFileSync(python as string, ["-I", join(dir, "functions.py"), join(dir, "lib.so")], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }),
    ) as { address: number; code: string }[];
    const base = 0x10000000;
    const lifted = await liftFunctions(python as string, "arm64", functions, join(dir, "lib.so"), base);
    const c = lifted.map((l) => ("c" in l ? l.c : "")).join("\n");
    writeFileSync(join(dir, "lifted.c"), `#include "atlas_lift.h"\n${c}`);
    const outcome = await a64linkProgram(python as string, {
      binary: join(dir, "lib.so"),
      lifted: [join(dir, "lifted.c")],
      translated: lifted.filter((l) => "c" in l).map((l) => Number(l.address)),
      out: join(dir, "host.so"),
      base,
    });
    writeFileSync(join(dir, "driver.c"), THREAD_DRIVER);
    execFileSync("gcc", ["-O1", "driver.c", "-o", "driver", "-ldl", "-lpthread"], { cwd: dir });
    const run = spawnSync(join(dir, "driver"), [outcome.executable], { encoding: "utf8" });
    expect(run.stdout).toBe("threads agree: 1\n");
  }, 600_000);
});

// An AArch64 program starting threads itself, with its own start routine: each runs on a host thread.
const THREAD_PROGRAM = `
#include <pthread.h>
#include <stdio.h>
static void *square(void *n) { long v = (long)n; return (void *)(v * v); }
int main(void) {
  pthread_t t[4];
  for (long k = 0; k < 4; k++) pthread_create(&t[k], 0, square, (void *)(k + 2));
  long sum = 0;
  for (int k = 0; k < 4; k++) { void *r; pthread_join(t[k], &r); sum += (long)r; }
  printf("sum of squares %ld\\n", sum);
  return 0;
}
`;

describe.runIf(python !== undefined && has("aarch64-linux-gnu-gcc"))("a64linkProgram guest threads", () => {
  it("runs the threads an AArch64 program starts with pthread_create", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-a64-guest-threads-test-"));
    writeFileSync(join(dir, "p.c"), THREAD_PROGRAM);
    execFileSync("aarch64-linux-gnu-gcc", ["-O1", "p.c", "-o", "p", "-lpthread"], { cwd: dir });
    writeFileSync(join(dir, "functions.py"), ELF_FUNCTIONS);
    const functions = JSON.parse(
      execFileSync(python as string, ["-I", join(dir, "functions.py"), join(dir, "p")], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }),
    ) as { address: number; code: string }[];
    const base = 0x10000000;
    const lifted = await liftFunctions(python as string, "arm64", functions, join(dir, "p"), base);
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
    expect(run.stdout).toBe("sum of squares 54\n");
    expect(run.status).toBe(0);
  }, 600_000);
});

// A translation made wrong on purpose (square returns 0), and the same function run as the original's own code
// instead: the program is right again. What atlas blame behaviour narrows a failing behaviour down with.
const SQUARE_PROGRAM = `
#include <stdio.h>
__attribute__((noinline)) int square(int x) { return x * x; }
int main(int argc, char **argv) { printf("%d\\n", square(argc + 6)); return 0; }
`;

describe.runIf(python !== undefined)("linkProgram native", () => {
  it("runs the functions named native as the original's machine code instead of their translation", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-native-test-"));
    writeFileSync(join(dir, "p.c"), SQUARE_PROGRAM);
    execFileSync("gcc", ["-O1", "-fcf-protection=none", "p.c", "-o", "p"], { cwd: dir });
    writeFileSync(join(dir, "functions.py"), ELF_FUNCTIONS);
    const functions = JSON.parse(
      execFileSync(python as string, ["-I", join(dir, "functions.py"), join(dir, "p")], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }),
    ) as { address: number; code: string }[];
    const nm = execFileSync("nm", [join(dir, "p")], { encoding: "utf8" });
    const square = Number.parseInt(/^([0-9a-f]+) T square$/m.exec(nm)?.[1] ?? "0", 16);
    const base = 0x10000000;
    const lifted = await liftFunctions(python as string, "x86_64", functions, join(dir, "p"), base);
    // The sabotage: square's translation returns 0 (rax), popping the return address as a ret would.
    const name = `fn_${(square + base).toString(16)}`;
    const c = lifted
      .map((l) => ("c" in l ? l.c : ""))
      .join("\n")
      .replace(
        `void ${name}(atlas_state *s) {`,
        `void ${name}(atlas_state *s) { REG(uint64_t, 16) = 0; REG(uint64_t, 48) += 8; return;`,
      );
    writeFileSync(join(dir, "lifted.c"), `#include "atlas_lift.h"\n${c}`);
    const link = async (native: number[]) =>
      linkProgram(python as string, {
        binary: join(dir, "p"),
        lifted: [join(dir, "lifted.c")],
        translated: lifted.filter((l) => "c" in l).map((l) => Number(l.address)),
        out: join(dir, `program-${native.length}`),
        rewrites: [],
        functions: {},
        base,
        native,
      });
    const wrong = await link([]);
    expect(spawnSync(wrong.executable, [], { encoding: "utf8" }).stdout).toBe("0\n");
    const right = await link([square]);
    expect(spawnSync(right.executable, [], { encoding: "utf8" }).stdout).toBe("49\n");
    // ATLAS_COVERAGE: the translated functions that ran (square is native in this link, main is translated).
    const coverage = join(dir, "coverage.txt");
    spawnSync(right.executable, [], { env: { ...process.env, ATLAS_COVERAGE: coverage } });
    const ran = readFileSync(coverage, "utf8")
      .trim()
      .split("\n")
      .map((a) => Number(a));
    const main = Number.parseInt(/^([0-9a-f]+) T main$/m.exec(nm)?.[1] ?? "0", 16);
    expect(ran).toContain(main);
    expect(ran).not.toContain(square);
    // The two links share the translations, compiled once.
    expect(readdirSync(dir).filter((f) => /^lifted\.c\.[0-9a-f]{16}\.o$/.test(f))).toHaveLength(1);
  }, 600_000);
});
