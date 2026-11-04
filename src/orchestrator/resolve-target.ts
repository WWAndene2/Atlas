// Turns the file the operator names into what an engine analyses. Most files go to the engines as they are. A
// container whose code is not directly analysable is opened first: for a 3DS title (NCSD or NCCH), the code is
// extracted, decompressed and laid out in a temporary file, then analysed as a raw ARMv6K image at its load address.
import { mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import type { EngineInput } from "../tools/engine-analysis.js";
import { ctrKind, readCtrCode, type CtrCode } from "../tools/ctr/index.js";

export interface ResolvedTarget {
  input: EngineInput;
  /** Label of the binary node: the operator's file name, with the part analysed when it is inside a container. */
  label: string;
  /** What was found inside, when the file is a container. */
  container?: Omit<CtrCode, "image">;
  /** Removes temporary files; call it once the engines are done. */
  dispose(): Promise<void>;
}

async function head(path: string, size: number): Promise<Uint8Array> {
  const file = await open(path, "r");
  try {
    const buffer = new Uint8Array(size);
    const { bytesRead } = await file.read(buffer, 0, size, 0);
    return buffer.subarray(0, bytesRead);
  } finally {
    await file.close();
  }
}

export async function resolveTarget(path: string, raw?: EngineInput["raw"]): Promise<ResolvedTarget> {
  const nothing = async (): Promise<void> => {};
  if (raw !== undefined) return { input: { path, raw }, label: basename(path), dispose: nothing };
  if (ctrKind(await head(path, 0x200)) === undefined)
    return { input: { path }, label: basename(path), dispose: nothing };

  const { image, ...container } = readCtrCode(new Uint8Array(await readFile(path)));
  const work = await mkdtemp(join(tmpdir(), "atlas-ctr-"));
  const codePath = join(work, "code.bin");
  await writeFile(codePath, image);
  return {
    input: { path: codePath, raw: { architecture: "arm-v6k", base: container.base } },
    label: `${basename(path)}:code.bin`,
    container,
    dispose: () => rm(work, { recursive: true, force: true }),
  };
}
