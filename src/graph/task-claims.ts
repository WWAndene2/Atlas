// Which agent works which task, so that agents working one graph in parallel never take the same one. A claim is a
// lease: it lapses after its time, and the task returns to the pool if its agent stopped (crashed, or its session
// ended) without releasing it. Claims coordinate work; they are not facts about the target, so they live in their own
// table beside the graph and are never exported.
import { DatabaseSync } from "node:sqlite";

export interface Claim {
  task: string;
  agent: string;
  /** Milliseconds since the epoch. */
  expires: number;
}

/** What an agent found on a task it gave back, for the next agent that takes it. */
export interface ReleaseNote {
  agent: string;
  note: string;
}

export class TaskClaims {
  private readonly db: DatabaseSync;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA busy_timeout = 30000;");
    if (path !== ":memory:") this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS claims (task TEXT PRIMARY KEY, agent TEXT NOT NULL, expires INTEGER NOT NULL)",
    );
    // Tasks given back, and how often: they go behind every task not yet tried.
    this.db.exec("CREATE TABLE IF NOT EXISTS released (task TEXT PRIMARY KEY, times INTEGER NOT NULL)");
    // What agents found before giving a task back (near misses, layouts, causes), so the next one starts from there.
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS release_notes (task TEXT NOT NULL, agent TEXT NOT NULL, note TEXT NOT NULL)",
    );
  }

  close(): void {
    this.db.close();
  }

  /**
   * Claims the first of `candidates` (in their order) that nobody holds, for `agent`, until `now + leaseMs`.
   * Atomic across processes: the read and the write happen under one write lock.
   */
  claimFirst(
    candidates: string[],
    agent: string,
    leaseMs: number,
    now = Date.now(),
    onlyReleased = false,
  ): Claim | undefined {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM claims WHERE expires <= ?").run(now);
      const held = new Set((this.db.prepare("SELECT task FROM claims").all() as { task: string }[]).map((r) => r.task));
      // Tasks never released first, in their order; then released ones, least released first. A released task went to
      // the front before, and in the first parallel run on Lua every claim after a release returned the same task.
      const times = new Map(
        (this.db.prepare("SELECT task, times FROM released").all() as { task: string; times: number }[]).map((r) => [
          r.task,
          r.times,
        ]),
      );
      const order = candidates
        .map((c, i) => ({ c, i, t: times.get(c) ?? 0 }))
        .sort((a, b) => a.t - b.t || a.i - b.i)
        .map((x) => x.c);
      // onlyReleased: an agent for the hard cases (a stronger model) takes only tasks others gave back.
      const task = order.find((c) => !held.has(c) && (!onlyReleased || (times.get(c) ?? 0) > 0));
      let claim: Claim | undefined;
      if (task !== undefined) {
        claim = { task, agent, expires: now + leaseMs };
        this.db.prepare("INSERT INTO claims (task, agent, expires) VALUES (?, ?, ?)").run(task, agent, claim.expires);
      }
      this.db.exec("COMMIT");
      return claim;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  /** Gives a task back. Only its holder can (another agent's release is ignored and reported false). */
  release(task: string, agent: string, note?: string): boolean {
    const released = this.db.prepare("DELETE FROM claims WHERE task = ? AND agent = ?").run(task, agent).changes > 0;
    if (released && note !== undefined && note.trim() !== "") {
      this.db.prepare("INSERT INTO release_notes (task, agent, note) VALUES (?, ?, ?)").run(task, agent, note.trim());
    }
    if (released) {
      this.db
        .prepare("INSERT INTO released (task, times) VALUES (?, 1) ON CONFLICT(task) DO UPDATE SET times = times + 1")
        .run(task);
    }
    return released;
  }

  /** The notes left on a task by the agents that gave it back, oldest first. */
  notes(task: string): ReleaseNote[] {
    return this.db
      .prepare("SELECT agent, note FROM release_notes WHERE task = ? ORDER BY rowid")
      .all(task) as unknown as ReleaseNote[];
  }

  /** The claims in force. */
  active(now = Date.now()): Claim[] {
    return this.db
      .prepare("SELECT task, agent, expires FROM claims WHERE expires > ? ORDER BY task")
      .all(now) as unknown as Claim[];
  }
}
