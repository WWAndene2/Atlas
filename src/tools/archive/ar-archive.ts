// Reads the members of a static library (an ar archive: .a, .lib), the format every Unix-family toolchain and MinGW
// use. "!<arch>\n", then members each behind a 60-byte header: name (16 bytes), size (10 bytes, decimal, at 48), and
// "`\n". GNU archives keep long names in a "//" member, referred to as "/<offset>"; "/" and "/SYM64/" are symbol
// indexes, not objects. BSD's "#1/<length>" names are also read.
export interface ArchiveMember {
  name: string;
  bytes: Uint8Array;
}

export class ArchiveError extends Error {
  constructor(message: string) {
    super(`archive: ${message}`);
    this.name = "ArchiveError";
  }
}

export function isArchive(bytes: Uint8Array): boolean {
  return new TextDecoder("latin1").decode(bytes.subarray(0, 8)) === "!<arch>\n";
}

export function archiveMembers(bytes: Uint8Array): ArchiveMember[] {
  if (!isArchive(bytes)) throw new ArchiveError("not an ar archive");
  const text = new TextDecoder("latin1");
  const members: ArchiveMember[] = [];
  let longNames = "";
  let at = 8;
  while (at + 60 <= bytes.length) {
    const header = text.decode(bytes.subarray(at, at + 60));
    if (header.slice(58, 60) !== "`\n") throw new ArchiveError(`bad member header at ${at}`);
    let name = header.slice(0, 16).trimEnd();
    const size = Number(header.slice(48, 58).trim());
    if (!Number.isInteger(size) || size < 0 || at + 60 + size > bytes.length)
      throw new ArchiveError(`bad size at ${at}`);
    let data = bytes.subarray(at + 60, at + 60 + size);
    if (name.startsWith("#1/")) {
      const length = Number(name.slice(3));
      name = text.decode(data.subarray(0, length)).replace(/\0+$/, "");
      data = data.subarray(length);
    }
    at += 60 + size + (size % 2); // members are 2-byte aligned
    if (name === "//") {
      longNames = text.decode(data);
      continue;
    }
    if (name === "/" || name === "/SYM64/" || name === "__.SYMDEF" || name === "__.SYMDEF SORTED") continue;
    if (/^\/\d+$/.test(name)) {
      const start = Number(name.slice(1));
      const end = longNames.indexOf("\n", start);
      name = longNames.slice(start, end < 0 ? undefined : end);
    }
    members.push({ name: name.replace(/\/$/, ""), bytes: data });
  }
  return members;
}
