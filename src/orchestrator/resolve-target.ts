// Turns the file the operator names into the binaries the engines analyse. A plain executable (ELF, PE, Mach-O, DEX)
// goes to the engines as it is: they read its header. A container is opened first by the reader for its format,
// recognised by content, never by file name:
//
// - 3DS title (NCSD, NCCH): the code, unpacked and laid out, as a raw ARMv6K image at its load address;
// - ZIP-based package (Android .apk/.aab, iOS .ipa, .jar, .zip): every member that is an executable (native .so
//   libraries for each ABI, DEX bytecode, Mach-O), each loaded as its own binary.
//
// Containers are read by offset (tools/byte-source.ts), never whole: game images and packages exceed what one read
// can return. Adding a format means one reader in src/tools/<format>/ and one opener here.
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { binaryKind } from "../tools/binary-kind.js";
import { fileSource } from "../tools/byte-source.js";
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
  /** Parts of a container that could not be read, with the reason; the others are still loaded. */
  unreadable: { label: string; reason: string }[];
  /** What the container was, when the file is one. */
  container?: { format: "3ds"; code: Omit<CtrCode, "image"> } | { format: "zip"; members: number };
  /** Removes temporary files; call it once the engines are done. */
  dispose(): Promise<void>;
}

/** Runs `fill` in a fresh temporary directory, which is removed if `fill` fails. */
async function inWorkDir<T>(prefix: string, fill: (work: string) => Promise<T>): Promise<{ work: string; result: T }> {
  const work = await mkdtemp(join(tmpdir(), prefix));
  try {
    return { work, result: await fill(work) };
  } catch (error) {
    await rm(work, { recursive: true, force: true });
    throw error;
  }
}

export async function resolveTarget(path: string, raw?: EngineInput["raw"]): Promise<ResolvedTarget> {
  const nothing = async (): Promise<void> => {};
  const name = basename(path);
  if (raw !== undefined) return { binaries: [{ input: { path, raw }, label: name }], unreadable: [], dispose: nothing };
  const source = fileSource(path);
  try {
    const start = source.read(0, 0x200);

    if (ctrKind(start) !== undefined) {
      const { image, ...code } = readCtrCode(source);
      const { work, result: codePath } = await inWorkDir("atlas-ctr-", async (dir) => {
        const file = join(dir, "code.bin");
        await writeFile(file, image);
        return file;
      });
      return {
        binaries: [
          { input: { path: codePath, raw: { architecture: "arm-v6k", base: code.base } }, label: `${name}:code.bin` },
        ],
        unreadable: [],
        container: { format: "3ds", code },
        dispose: () => rm(work, { recursive: true, force: true }),
      };
    }

    if (isZip(start)) {
      const members = zipMembers(source);
      const unreadable: ResolvedTarget["unreadable"] = [];
      const { work, result: binaries } = await inWorkDir("atlas-zip-", async (dir) => {
        const found: ResolvedBinary[] = [];
        for (const member of members) {
          if (member.size < 8) continue;
          const label = `${name}:${member.name}`;
          try {
            // Only the first bytes decide; the member is read in full only when it is an executable.
            if (binaryKind(member.peek(8)) === undefined) continue;
            // Member names are target data: the file on disk gets a plain numbered name, never the member's path.
            const file = join(dir, `${found.length}.bin`);
            await writeFile(file, member.read());
            found.push({ input: { path: file }, label });
          } catch (error) {
            unreadable.push({ label, reason: (error as Error).message });
          }
        }
        return found;
      });
      return {
        binaries,
        unreadable,
        container: { format: "zip", members: members.length },
        dispose: () => rm(work, { recursive: true, force: true }),
      };
    }

    return { binaries: [{ input: { path }, label: name }], unreadable: [], dispose: nothing };
  } finally {
    source.close();
  }
}
