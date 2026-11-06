// The knowledge graph's storage: one SQLite file per project. Every record is validated against schema/ on the way in,
// and the store enforces the rules a schema cannot express (ID prefix by kind, references to existing nodes, and
// verification results written only through recordVerification).
import { DatabaseSync } from "node:sqlite";
import { NODE_ID_PREFIX } from "./model.js";
import type { Confidence, Evidence, GraphEdge, GraphNode, Hypothesis } from "./model.js";
import { assertEdge, assertEvidence, assertHypothesis, assertNode } from "./schema-validators.js";

export class GraphIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GraphIntegrityError";
  }
}

/** The outcome the verification loop records on a hypothesis. */
export interface VerificationRecord {
  confidence: Confidence;
  verification: NonNullable<Hypothesis["verification"]>;
}

const SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, kind TEXT NOT NULL, record TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS edges (
    source TEXT NOT NULL REFERENCES nodes(id),
    kind TEXT NOT NULL,
    target TEXT NOT NULL REFERENCES nodes(id),
    record TEXT NOT NULL,
    PRIMARY KEY (source, kind, target)
  );
  CREATE INDEX IF NOT EXISTS edges_by_target ON edges (target, kind);
  CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, record TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    node TEXT NOT NULL REFERENCES nodes(id),
    kind TEXT NOT NULL,
    confidence TEXT NOT NULL,
    record TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS hypotheses_by_node ON hypotheses (node, kind);
`;

export class GraphStore {
  private readonly db: DatabaseSync;

  /** Opens (or creates) a graph. `path` is a file, or ":memory:" for a throwaway graph. */
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    // Several agents work one graph at once, each through its own process: a writer waits for another's lock rather
    // than failing, and readers do not block the writer (WAL; a no-op for an in-memory graph).
    this.db.exec("PRAGMA busy_timeout = 30000;");
    if (path !== ":memory:") this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA foreign_keys = ON;");
    this.db.exec(SCHEMA_SQL);
  }

  close(): void {
    this.db.close();
  }

  putNode(node: GraphNode): void {
    assertNode(node);
    const prefix = NODE_ID_PREFIX[node.kind];
    if (!node.id.startsWith(prefix)) {
      throw new GraphIntegrityError(`node ${node.id}: a ${node.kind} ID starts with ${prefix}`);
    }
    if (node.kind === "binary") {
      if (node.binary !== undefined) throw new GraphIntegrityError(`node ${node.id}: a binary has no binary field`);
    } else {
      if (node.binary === undefined) throw new GraphIntegrityError(`node ${node.id}: missing its binary`);
      if (this.getNode(node.binary)?.kind !== "binary") {
        throw new GraphIntegrityError(`node ${node.id}: binary ${node.binary} is not in the graph`);
      }
    }
    this.db
      .prepare(
        "INSERT INTO nodes (id, kind, record) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET record = excluded.record",
      )
      .run(node.id, node.kind, JSON.stringify(node));
  }

  getNode(id: string): GraphNode | undefined {
    const row = this.db.prepare("SELECT record FROM nodes WHERE id = ?").get(id) as { record: string } | undefined;
    return row === undefined ? undefined : (JSON.parse(row.record) as GraphNode);
  }

  /** Every node of one kind, by ID. */
  nodesOfKind(kind: GraphNode["kind"]): GraphNode[] {
    const rows = this.db.prepare("SELECT record FROM nodes WHERE kind = ? ORDER BY id").all(kind) as {
      record: string;
    }[];
    return rows.map((row) => JSON.parse(row.record) as GraphNode);
  }

  putEdge(edge: GraphEdge): void {
    assertEdge(edge);
    for (const end of [edge.from, edge.to]) {
      if (this.getNode(end) === undefined)
        throw new GraphIntegrityError(`edge ${edge.kind}: node ${end} is not in the graph`);
    }
    this.db
      .prepare(
        "INSERT INTO edges (source, kind, target, record) VALUES (?, ?, ?, ?) " +
          "ON CONFLICT(source, kind, target) DO UPDATE SET record = excluded.record",
      )
      .run(edge.from, edge.kind, edge.to, JSON.stringify(edge));
  }

  edgesFrom(id: string, kind?: GraphEdge["kind"]): GraphEdge[] {
    return this.readEdges("source", id, kind);
  }

  edgesTo(id: string, kind?: GraphEdge["kind"]): GraphEdge[] {
    return this.readEdges("target", id, kind);
  }

  putEvidence(evidence: Evidence): void {
    assertEvidence(evidence);
    this.db
      .prepare("INSERT INTO evidence (id, record) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET record = excluded.record")
      .run(evidence.id, JSON.stringify(evidence));
  }

  getEvidence(id: string): Evidence | undefined {
    const row = this.db.prepare("SELECT record FROM evidence WHERE id = ?").get(id) as { record: string } | undefined;
    return row === undefined ? undefined : (JSON.parse(row.record) as Evidence);
  }

  /**
   * Adds an agent's hypothesis. Agents never set the verification outcome (AGENTS.md section 1.2): `verified`,
   * `rejected` and the `verification` field are refused here and written only by recordVerification.
   */
  proposeHypothesis(hypothesis: Hypothesis): void {
    assertHypothesis(hypothesis);
    if (hypothesis.confidence === "verified" || hypothesis.confidence === "rejected") {
      throw new GraphIntegrityError(
        `hypothesis ${hypothesis.id}: only the verification loop sets ${hypothesis.confidence}`,
      );
    }
    if (hypothesis.verification !== undefined) {
      throw new GraphIntegrityError(`hypothesis ${hypothesis.id}: only the verification loop fills verification`);
    }
    if (this.getNode(hypothesis.node) === undefined) {
      throw new GraphIntegrityError(`hypothesis ${hypothesis.id}: node ${hypothesis.node} is not in the graph`);
    }
    if (this.getHypothesis(hypothesis.id) !== undefined) {
      throw new GraphIntegrityError(`hypothesis ${hypothesis.id} already exists; propose a new one instead`);
    }
    this.writeHypothesis(hypothesis);
  }

  /** Records a check's outcome on a hypothesis. Reserved for the verification loop (src/verify/). */
  recordVerification(id: string, outcome: VerificationRecord): Hypothesis {
    const current = this.getHypothesis(id);
    if (current === undefined) throw new GraphIntegrityError(`hypothesis ${id} is not in the graph`);
    const updated: Hypothesis = { ...current, confidence: outcome.confidence, verification: outcome.verification };
    assertHypothesis(updated);
    this.writeHypothesis(updated);
    return updated;
  }

  /**
   * Writes a hypothesis exactly as recorded, outcome included. Reserved for importing a reviewed export
   * (graph-jsonl.ts): an import replays a graph, it is not an agent proposing facts.
   */
  restoreHypothesis(hypothesis: Hypothesis): void {
    assertHypothesis(hypothesis);
    if (this.getNode(hypothesis.node) === undefined) {
      throw new GraphIntegrityError(`hypothesis ${hypothesis.id}: node ${hypothesis.node} is not in the graph`);
    }
    this.writeHypothesis(hypothesis);
  }

  getHypothesis(id: string): Hypothesis | undefined {
    const row = this.db.prepare("SELECT record FROM hypotheses WHERE id = ?").get(id) as { record: string } | undefined;
    return row === undefined ? undefined : (JSON.parse(row.record) as Hypothesis);
  }

  /** A node's hypotheses in the order they were added (an import adds them in its file's order). */
  hypothesesFor(nodeId: string, kind?: Hypothesis["kind"]): Hypothesis[] {
    const rows = (
      kind === undefined
        ? this.db.prepare("SELECT record FROM hypotheses WHERE node = ? ORDER BY rowid").all(nodeId)
        : this.db.prepare("SELECT record FROM hypotheses WHERE node = ? AND kind = ? ORDER BY rowid").all(nodeId, kind)
    ) as { record: string }[];
    return rows.map((row) => JSON.parse(row.record) as Hypothesis);
  }

  /** Every record of one table, ordered by key, for export. */
  allRecords(table: "nodes" | "edges" | "evidence" | "hypotheses"): unknown[] {
    const order = table === "edges" ? "source, kind, target" : "id";
    const rows = this.db.prepare(`SELECT record FROM ${table} ORDER BY ${order}`).all() as { record: string }[];
    return rows.map((row) => JSON.parse(row.record) as unknown);
  }

  /** Runs `work` in one transaction: all of it is written, or none. */
  transaction(work: () => void): void {
    // IMMEDIATE takes the write lock at once: two processes reading then writing cannot deadlock on an upgrade.
    this.db.exec("BEGIN IMMEDIATE");
    try {
      work();
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  private writeHypothesis(hypothesis: Hypothesis): void {
    this.db
      .prepare(
        "INSERT INTO hypotheses (id, node, kind, confidence, record) VALUES (?, ?, ?, ?, ?) " +
          "ON CONFLICT(id) DO UPDATE SET confidence = excluded.confidence, record = excluded.record",
      )
      .run(hypothesis.id, hypothesis.node, hypothesis.kind, hypothesis.confidence, JSON.stringify(hypothesis));
  }

  private readEdges(column: "source" | "target", id: string, kind?: GraphEdge["kind"]): GraphEdge[] {
    const rows = (
      kind === undefined
        ? this.db.prepare(`SELECT record FROM edges WHERE ${column} = ? ORDER BY source, kind, target`).all(id)
        : this.db
            .prepare(`SELECT record FROM edges WHERE ${column} = ? AND kind = ? ORDER BY source, kind, target`)
            .all(id, kind)
    ) as { record: string }[];
    return rows.map((row) => JSON.parse(row.record) as GraphEdge);
  }
}
