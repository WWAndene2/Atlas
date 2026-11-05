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

export class TaskClaims {
  private readonly db: DatabaseSync;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA busy_timeout = 30000;");
    if (path !== ":memory:") this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS claims (task TEXT PRIMARY KEY, agent TEXT NOT NULL, expires INTEGER NOT NULL)",
    );
  }

  close(): void {
    this.db.close();
  }

  /**
   * Claims the first of `candidates` (in their order) that nobody holds, for `agent`, until `now + leaseMs`.
   * Atomic across processes: the read and the write happen under one write lock.
   */
  claimFirst(candidates: string[], agent: string, leaseMs: number, now = Date.now()): Claim | undefined {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM claims WHERE expires <= ?").run(now);
      const held = new Set((this.db.prepare("SELECT task FROM claims").all() as { task: string }[]).map((r) => r.task));
      const task = candidates.find((c) => !held.has(c));
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
  release(task: string, agent: string): boolean {
    return this.db.prepare("DELETE FROM claims WHERE task = ? AND agent = ?").run(task, agent).changes > 0;
  }

  /** The claims in force. */
  active(now = Date.now()): Claim[] {
    return this.db
      .prepare("SELECT task, agent, expires FROM claims WHERE expires > ? ORDER BY task")
      .all(now) as unknown as Claim[];
  }
}
