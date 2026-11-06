// Routes tasks to agents of different strength. A task's level is its size tier (how many size bounds its function
// exceeds) plus the times it was given back, capped at the top level; an agent at level k takes only tasks at level
// k. Small functions go to the cheapest agents, large ones to the strongest, and what a level gives back moves up to
// the next: escalation needs no other rule.
//
// Bounds measured on x86-64 Lua (5 claims, 3 proposals per agent): Haiku verified functions up to 148 bytes and
// released the largest untried; Sonnet verified up to 177 bytes with near misses at 294 and 323; Opus verified up to
// 503. Hence 160 and 400 by default; to revisit on other targets.

export interface Levels {
  /** Number of levels (1 to 3 in the modes in use). */
  of: number;
  /** Size bounds in bytes, ascending; a function above bound i is at least at level i + 1. At most of - 1 bounds. */
  bounds: number[];
}

export function taskLevel(size: number, releases: number, levels: Levels): number {
  const base = levels.bounds.filter((b) => size > b).length;
  return Math.min(base + releases, levels.of - 1);
}

export function parseLevels(of: string | undefined, bounds: string | undefined): Levels {
  const n = Number(of ?? "1");
  const b = (bounds ?? "")
    .split(",")
    .filter((x) => x.trim() !== "")
    .map(Number);
  if (!Number.isInteger(n) || n < 1) throw new Error("--of takes the number of levels (1 or more)");
  if (
    b.some((x) => !Number.isFinite(x) || x < 0) ||
    b.length > n - 1 ||
    b.some((x, i) => i > 0 && x <= (b[i - 1] ?? 0))
  ) {
    throw new Error("--bounds takes ascending sizes in bytes, at most one fewer than the levels");
  }
  return { of: n, bounds: b };
}
