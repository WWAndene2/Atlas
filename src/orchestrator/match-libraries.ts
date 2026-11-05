// Recognises library code in a binary: functions identical to a function of a static library the toolchain ships
// (libgcc, the C library, the maths library) or the operator gives. Such code is linked, not rewritten: a match gives
// the function a match hypothesis and a name, and takes it out of the rewrite queue.
//
// A library function is its bytes in the library's object file with the bytes relocations fill masked; a binary's
// function matches when its code equals those bytes outside the mask. Functions are looked up by their first 8
// bytes (relocated ones zeroed), then compared in full. Short functions (under 12 bytes) are not matched:
// too many unrelated ones are identical. Libraries are read whole, so a few thousand objects take a minute or two.
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import type { GraphStore, Hypothesis } from "../graph/index.js";
import { archiveMembers, isArchive } from "../tools/archive/index.js";
import { objectFunctions, readObjectFile } from "../verify/recompile/object-file.js";
import { forEachConcurrently } from "./parallel.js";
import { proposeName } from "./propose-name.js";

export interface LibraryFunction {
  library: string;
  object: string;
  name: string;
  bytes: Uint8Array;
  mask: Uint8Array;
}

const MINIMUM = 12;

/** Every function of a static library (.a) or object (.o), ready to match. Unreadable members are skipped. */
export async function libraryFunctions(path: string): Promise<LibraryFunction[]> {
  const bytes = new Uint8Array(await readFile(path));
  const members = isArchive(bytes) ? archiveMembers(bytes) : [{ name: basename(path), bytes }];
  const work = await mkdtemp(join(tmpdir(), "atlas-lib-"));
  const out: LibraryFunction[] = [];
  try {
    await forEachConcurrently(
      members.map((m, i) => ({ ...m, index: i })),
      async (m) => {
        const file = join(work, `${m.index}.o`);
        await writeFile(file, m.bytes);
        try {
          for (const f of objectFunctions(await readObjectFile(file))) {
            if (f.bytes.length < MINIMUM) continue;
            const mask = new Uint8Array(f.bytes.length);
            for (const r of f.relocations) mask.fill(1, r.offset, Math.min(r.offset + r.width, mask.length));
            out.push({ library: basename(path), object: m.name, name: f.name, bytes: new Uint8Array(f.bytes), mask });
          }
        } catch {
          // Not an object Atlas reads (a linker script, another format): nothing to match from it.
        }
      },
    );
  } finally {
    await rm(work, { recursive: true, force: true });
  }
  return out;
}

/** The first 8 bytes with the relocated ones (per `mask`, a string of 8 "0"/"1") zeroed: the lookup key. */
const prefixKey = (bytes: Uint8Array, mask: string): string =>
  Array.from(bytes.subarray(0, 8), (b, i) => (mask[i] === "1" ? "00" : b.toString(16).padStart(2, "0"))).join("");

function matches(code: Uint8Array, f: LibraryFunction): boolean {
  if (code.length < f.bytes.length) return false;
  for (let i = 0; i < f.bytes.length; i++) if (f.mask[i] === 0 && code[i] !== f.bytes[i]) return false;
  return true;
}

export interface MatchOutcome {
  matched: number;
  /** Matches naming a single function, for which a name hypothesis was added. */
  named: number;
  libraries: { path: string; functions: number }[];
}

export async function matchLibraries(store: GraphStore, binary: string, libraries: string[]): Promise<MatchOutcome> {
  // Indexed by the first 8 bytes with their relocated bytes zeroed, grouped by which of those 8 are relocated: a
  // function starting with a relocated address (crtstuff's deregister_tm_clones begins with a lea) is found too. A
  // binary's function is looked up once per pattern; there are few.
  const index = new Map<string, Map<string, LibraryFunction[]>>();
  const outcome: MatchOutcome = { matched: 0, named: 0, libraries: [] };
  for (const path of libraries) {
    const functions = await libraryFunctions(path);
    outcome.libraries.push({ path, functions: functions.length });
    for (const f of functions) {
      const pattern = Array.from(f.mask.subarray(0, 8), String).join("");
      const byKey = index.get(pattern) ?? new Map<string, LibraryFunction[]>();
      const key = prefixKey(f.bytes, pattern);
      byKey.set(key, [...(byKey.get(key) ?? []), f]);
      index.set(pattern, byKey);
    }
  }
  const functions = store.nodesOfKind("function").filter((n) => n.binary === binary && n.code !== undefined);
  store.transaction(() => {
    for (const fn of functions) {
      const code = Buffer.from(fn.code ?? "", "hex");
      // The longest match wins: a short library function can be a prefix of a longer one.
      const found = [...index]
        .flatMap(([pattern, byKey]) => byKey.get(prefixKey(code, pattern)) ?? [])
        .filter((f) => matches(code, f))
        .sort((a, b) => b.bytes.length - a.bytes.length);
      const best = found[0];
      if (best === undefined || (fn.size !== undefined && best.bytes.length < fn.size)) continue;
      const same = found.filter((f) => f.bytes.length === best.bytes.length);
      const names = [...new Set(same.map((f) => f.name))].sort();
      const value = { library: best.library, object: best.object, names, size: best.bytes.length };
      const id = `hyp_${createHash("sha256")
        .update(`${fn.id}\nmatch\n${JSON.stringify(value)}`)
        .digest("hex")
        .slice(0, 32)}`;
      if (store.getHypothesis(id) === undefined) {
        const hypothesis: Hypothesis = {
          schema_version: 1,
          id,
          node: fn.id,
          kind: "match",
          value,
          confidence: "inferred",
          evidence: [fn.id],
          author: { agent: "library-matcher" },
        };
        store.proposeHypothesis(hypothesis);
      }
      outcome.matched++;
      if (names.length === 1 && names[0] !== undefined) {
        proposeName(store, fn.id, names[0], "library-matcher");
        outcome.named++;
      }
    }
  });
  return outcome;
}
