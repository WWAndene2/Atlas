// Kaitai Struct: a file format described in .ksy is compiled to a Python parser (kaitai-struct-compiler, Java) and
// run on files of that kind (parse.py, with the kaitaistruct runtime in the tools Python environment). Both are
// installed by scripts/setup.sh at the reviewed versions (docs/DEPENDENCY_REVIEWS.md).
import { execFile, execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { repositoryPath } from "../../graph/index.js";
import { toolsDir } from "../tools-dir.js";

const run = promisify(execFile);

export const KAITAI_VERSION = "0.11";

export class KaitaiUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KaitaiUnavailableError";
  }
}

export class KsyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KsyError";
  }
}

export interface ParsedFile {
  path: string;
  ok: boolean;
  /** Bytes the top-level structure read; less than size means trailing bytes the format does not describe. */
  consumed: number;
  size: number;
  error?: string;
}

export function locateKaitai(env: NodeJS.ProcessEnv = process.env): { compiler: string; python: string } {
  const compiler = join(toolsDir(env), `kaitai-struct-compiler-${KAITAI_VERSION}`, "bin", "kaitai-struct-compiler");
  const python = join(toolsDir(env), "py", "bin", "python");
  const missing = new KaitaiUnavailableError(
    `no Kaitai Struct ${KAITAI_VERSION} in ${toolsDir(env)}; run scripts/setup.sh`,
  );
  if (!existsSync(compiler) || !existsSync(python)) throw missing;
  try {
    execFileSync(python, ["-c", "import kaitaistruct"], { stdio: "ignore" });
  } catch {
    throw missing;
  }
  return { compiler, python };
}

/** Kaitai's class name for a format id: snake_case to UpperCamelCase. */
function className(id: string): string {
  return id
    .split("_")
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join("");
}

export async function parseWithKsy(
  tools: { compiler: string; python: string },
  ksy: string,
  files: string[],
  timeoutMs = 300_000,
): Promise<{ id: string; files: ParsedFile[] }> {
  const id = /^meta:\s*\n(?:[ \t]+.*\n)*?[ \t]+id:\s*([a-z][a-z0-9_]*)\s*$/m.exec(ksy)?.[1];
  if (id === undefined) throw new KsyError("the .ksy has no meta: id: (lowercase snake_case)");
  const work = await mkdtemp(join(tmpdir(), "atlas-kaitai-"));
  try {
    await writeFile(join(work, `${id}.ksy`), ksy);
    try {
      await run(tools.compiler, ["-t", "python", "--outdir", join(work, "out"), join(work, `${id}.ksy`)], {
        timeout: timeoutMs,
      });
    } catch (error) {
      const stderr = (error as { stderr?: string }).stderr ?? (error as Error).message;
      throw new KsyError(
        `the .ksy does not compile: ${stderr
          .split("\n")
          .filter((l) => !l.startsWith("Picked up"))
          .join(" ")
          .slice(0, 500)}`,
      );
    }
    if (!(await readdir(join(work, "out"))).includes(`${id}.py`)) throw new KsyError("the compiler wrote no parser");
    await writeFile(join(work, "request.json"), JSON.stringify({ files }));
    const { stdout } = await run(
      tools.python,
      [
        repositoryPath("src", "tools", "kaitai", "parse.py"),
        join(work, "out"),
        id,
        className(id),
        join(work, "request.json"),
      ],
      { timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 },
    );
    return { id, files: (JSON.parse(stdout.trim().split("\n").pop() ?? "{}") as { files: ParsedFile[] }).files };
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
