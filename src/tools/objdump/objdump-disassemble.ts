// Disassembles raw machine code with GNU objdump, the copy built for the architecture (each cross toolchain brings
// its own; setup.sh installs them). Raw bytes in, so it serves a function's original code from the graph and a
// candidate's compiled code alike, at whatever address they belong.
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type { Architecture } from "../engine-analysis.js";

const run = promisify(execFile);

export interface Instruction {
  address: string;
  /** The instruction's bytes, hex. */
  bytes: string;
  /** Mnemonic and operands as objdump prints them. */
  text: string;
}

const TOOL: Record<Architecture, { command: string; machine: string }> = {
  x86_64: { command: "objdump", machine: "i386:x86-64" },
  x86: { command: "objdump", machine: "i386" },
  arm64: { command: "aarch64-linux-gnu-objdump", machine: "aarch64" },
  "arm-v7": { command: "arm-none-eabi-objdump", machine: "arm" },
  "arm-v6k": { command: "arm-none-eabi-objdump", machine: "arm" },
  "arm-v5te": { command: "arm-none-eabi-objdump", machine: "arm" },
};

export class DisassembleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DisassembleError";
  }
}

export async function disassemble(
  code: Uint8Array,
  architecture: Architecture,
  address: string,
  options: { thumb?: boolean } = {},
): Promise<Instruction[]> {
  if (code.length === 0) return [];
  const { command, machine } = TOOL[architecture];
  const work = await mkdtemp(join(tmpdir(), "atlas-objdump-"));
  try {
    const file = join(work, "code.bin");
    await writeFile(file, code);
    const args = ["-D", "-b", "binary", "-m", machine, `--adjust-vma=${address}`, "--no-show-raw-insn", "-z"];
    if (options.thumb === true) args.push("-M", "force-thumb");
    let stdout: string;
    try {
      ({ stdout } = await run(command, [...args, file], { maxBuffer: 64 * 1024 * 1024 }));
    } catch (error) {
      throw new DisassembleError(`${command} could not disassemble ${architecture} code: ${(error as Error).message}`);
    }
    // Lines look like "  100004:\tmov    %rdi,%rax"; the bytes are taken from the input by address difference.
    const lines = [...stdout.matchAll(/^\s*([0-9a-f]+):\t(.+)$/gm)].map((m) => ({
      address: BigInt(`0x${m[1] ?? "0"}`),
      text: (m[2] ?? "").replace(/\s+/g, " ").trim(),
    }));
    const start = BigInt(address);
    return lines.map((line, i) => {
      const from = Number(line.address - start);
      const to = i + 1 < lines.length ? Number((lines[i + 1]?.address ?? 0n) - start) : code.length;
      return {
        address: `0x${line.address.toString(16)}`,
        bytes: Buffer.from(code.subarray(from, to)).toString("hex"),
        text: line.text,
      };
    });
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
