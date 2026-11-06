// Mutations of a behaviour scenario's inputs, for differential testing (atlas fuzz behaviour): the standard input
// and the input files' bytes are flipped, replaced, inserted, deleted or duplicated, a few at a time, from a seeded
// generator so that a run can be repeated exactly. Arguments, environment and output names are kept: a mutant asks
// the same program the same question about different data.
import { decode, encode, type Scenario } from "./run-scenario.js";

/** A small seeded generator (mulberry32): the same seed gives the same mutants. */
export function generator(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Bytes that often change how a parser or interpreter reads its input.
const INTERESTING = [0x00, 0x0a, 0x20, 0x22, 0x27, 0x28, 0x29, 0x2d, 0x30, 0x39, 0x5c, 0x7b, 0x7d, 0x7f, 0xff];

function mutateBytes(input: Buffer, random: () => number): Buffer {
  const bytes = [...input];
  const edits = 1 + Math.floor(random() * 3);
  for (let e = 0; e < edits; e++) {
    const at = Math.floor(random() * (bytes.length + 1));
    const pick = () =>
      random() < 0.5 ? (INTERESTING[Math.floor(random() * INTERESTING.length)] as number) : Math.floor(random() * 256);
    switch (Math.floor(random() * 5)) {
      case 0: // flip a bit
        if (at < bytes.length) bytes[at] = (bytes[at] as number) ^ (1 << Math.floor(random() * 8));
        break;
      case 1: // replace a byte
        if (at < bytes.length) bytes[at] = pick();
        break;
      case 2: // insert a byte
        bytes.splice(at, 0, pick());
        break;
      case 3: // delete a run
        bytes.splice(at, 1 + Math.floor(random() * 4));
        break;
      default: {
        // duplicate a run
        const run = bytes.slice(at, at + 1 + Math.floor(random() * 8));
        bytes.splice(at, 0, ...run);
      }
    }
  }
  return Buffer.from(bytes);
}

/** A mutant of the scenario, or undefined when it has no input to mutate (no standard input, no input file). */
export function mutateScenario(scenario: Scenario, random: () => number): Scenario | undefined {
  const targets = (scenario.stdin !== undefined ? 1 : 0) + (scenario.inputs?.length ?? 0);
  if (targets === 0) return undefined;
  const which = Math.floor(random() * targets);
  if (scenario.stdin !== undefined && which === 0) {
    // The standard input is text, sent as UTF-8: a byte that is not valid becomes U+FFFD, the same each time.
    return { ...scenario, stdin: mutateBytes(Buffer.from(scenario.stdin, "utf8"), random).toString("utf8") };
  }
  const k = which - (scenario.stdin !== undefined ? 1 : 0);
  const inputs = (scenario.inputs ?? []).map((input, i) =>
    i === k ? { name: input.name, content: encode(mutateBytes(decode(input.content), random)) } : input,
  );
  return { ...scenario, inputs };
}
