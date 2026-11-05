// A file format hypothesis checked the way ARCHITECTURE.md asks: the parser generated from it must read every file
// of that kind. The format is a .ksy (Kaitai Struct) an agent wrote, usually from the loader code that reads the
// files; it becomes a format node (fmt_<binary>_<id>) with a format hypothesis holding the .ksy, and the parser's run on the
// files given is its verification (check parser_run): every file read whole makes it verified, a failure is recorded
// with the file and the error. Running it again with more files re-checks the same hypothesis.
import { createHash } from "node:crypto";
import type { GraphStore, Hypothesis } from "../graph/index.js";
import { NotFoundError } from "./function-context.js";
import { locateKaitai, parseWithKsy, type ParsedFile } from "../tools/kaitai/index.js";

export interface FormatCheck {
  format: string;
  hypothesis: Hypothesis;
  files: ParsedFile[];
}

export async function checkFormat(
  store: GraphStore,
  ksy: string,
  files: string[],
  options: { agent?: string; binary?: string } = {},
): Promise<FormatCheck> {
  // A format belongs to the binary that reads it: the one named, or the graph's only binary.
  const binaries = store.nodesOfKind("binary").map((b) => b.id);
  const binary = options.binary ?? (binaries.length === 1 ? binaries[0] : undefined);
  if (binary === undefined || store.getNode(binary)?.kind !== "binary") {
    throw new NotFoundError(
      binaries.length === 0
        ? "no binary loaded: load the program that reads these files first"
        : "name the binary that reads these files (--binary)",
    );
  }
  const parsed = await parseWithKsy(locateKaitai(), ksy, files);
  const format = `fmt_${binary.slice(4)}_${parsed.id}`;
  const id = `hyp_${createHash("sha256").update(`${format}\nformat\n${ksy}`).digest("hex").slice(0, 32)}`;
  store.transaction(() => {
    if (store.getNode(format) === undefined) {
      store.putNode({
        schema_version: 1,
        id: format,
        kind: "format",
        label: parsed.id,
        binary,
      });
    }
    if (store.getHypothesis(id) === undefined) {
      store.proposeHypothesis({
        schema_version: 1,
        id,
        node: format,
        kind: "format",
        value: { ksy },
        confidence: "inferred",
        evidence: [format],
        author: { agent: options.agent ?? "agent" },
      });
    }
  });
  const failed = parsed.files.find((f) => !f.ok);
  const partial = parsed.files.filter((f) => f.ok && f.consumed < f.size);
  const pass = failed === undefined && files.length > 0;
  const details =
    failed !== undefined
      ? `${failed.path}: ${failed.error ?? "parse failed"} (${parsed.files.filter((f) => f.ok).length} of ${files.length} files read)`
      : `${files.length} files read` +
        (partial.length > 0 ? `; ${partial.length} with trailing bytes the format does not describe` : "");
  const hypothesis = store.recordVerification(id, {
    confidence: pass ? "verified" : "inferred",
    verification: { check: "parser_run", result: pass ? "pass" : "fail", details },
  });
  return { format, hypothesis, files: parsed.files };
}
