import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ArchiveError, archiveMembers, isArchive } from "../../../src/tools/archive/index.js";

describe("archiveMembers", () => {
  it("reads the members of an archive made by ar, long names included", () => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-ar-"));
    const long = "a_member_name_longer_than_sixteen_bytes.o";
    writeFileSync(join(dir, "a.o"), "first");
    writeFileSync(join(dir, long), "second member");
    execFileSync("ar", ["rcs", join(dir, "lib.a"), join(dir, "a.o"), join(dir, long)]);
    const bytes = new Uint8Array(readFileSync(join(dir, "lib.a")));
    expect(isArchive(bytes)).toBe(true);
    const members = archiveMembers(bytes);
    expect(members.map((m) => m.name)).toEqual(["a.o", long]);
    expect(new TextDecoder().decode(members[1]?.bytes)).toBe("second member");
  });

  it("refuses what is not an archive", () => {
    expect(() => archiveMembers(new TextEncoder().encode("not an archive"))).toThrow(ArchiveError);
  });
});
