// Turns the file the operator names into the binaries the engines analyse. A plain executable (ELF, PE, Mach-O, DEX)
// goes to the engines as it is: they read its header. A container is opened first by the reader for its format,
// recognised by content, never by file name:
//
// - 3DS title (NCSD, NCCH): the code, unpacked and laid out, as a raw ARMv6K image at its load address;
// - ZIP-based package (Android .apk/.aab, iOS .ipa, .jar, .zip): every member that is an executable (native .so
//   libraries for each ABI, DEX bytecode, Mach-O), each loaded as its own binary.
//
// Adding a format means one reader in src/tools/<format>/ and one opener here.
import { mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { binaryKind } from "../tools/binary-kind.js";
import { ctrKind, readCtrCode, type CtrCode } from "../tools/ctr/index.js";
import type { EngineInput } from "../tools/engine-analysis.js";
import { isZip, zipMembers } from "../tools/zip/index.js";

export interface ResolvedBinary {
  input: EngineInput;
  /** Label of the binary node: the operator's file name, then the path of the part inside a container. */
  label: string;
}

export interface ResolvedTarget {
  binaries: ResolvedBinary[];
  /** What the container was, when the file is one. */
  container?: { format: "3ds"; code: Omit<CtrCode, "image"> } | { format: "zip"; members: number };
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
  const name = basename(path);
  if (raw !== undefined) return { binaries: [{ input: { path, raw }, label: name }], dispose: nothing };
  const start = await head(path, 0x200);

  if (ctrKind(start) !== undefined) {
    const { image, ...code } = readCtrCode(new Uint8Array(await readFile(path)));
    const work = await mkdtemp(join(tmpdir(), "atlas-ctr-"));
    const codePath = join(work, "code.bin");
    await writeFile(codePath, image);
    return {
      binaries: [
        { input: { path: codePath, raw: { architecture: "arm-v6k", base: code.base } }, label: `${name}:code.bin` },
      ],
      container: { format: "3ds", code },
      dispose: () => rm(work, { recursive: true, force: true }),
    };
  }

  if (isZip(start)) {
    const members = zipMembers(new Uint8Array(await readFile(path)));
    const work = await mkdtemp(join(tmpdir(), "atlas-zip-"));
    const binaries: ResolvedBinary[] = [];
    for (const member of members) {
      if (member.size < 8) continue;
      const bytes = member.read();
      if (binaryKind(bytes) === undefined) continue;
      // Member names are target data: the file on disk gets a plain numbered name, never the member's path.
      const file = join(work, `${binaries.length}.bin`);
      await writeFile(file, bytes);
      binaries.push({ input: { path: file }, label: `${name}:${member.name}` });
    }
    return {
      binaries,
      container: { format: "zip", members: members.length },
      dispose: () => rm(work, { recursive: true, force: true }),
    };
  }

  return { binaries: [{ input: { path }, label: name }], dispose: nothing };
}
