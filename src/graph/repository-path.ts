// Files Atlas reads from its own checkout at run time (the schemas, the Ghidra script) are not copied to dist/ by
// tsc, so they are found from the repository root: the nearest directory above this module holding package.json.
// The same lookup works from src/ (tests) and dist/ (the built CLI). In the graph layer because it is the lowest
// layer that needs it; every layer above may import it.
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

let root: string | undefined;

export function repositoryPath(...segments: string[]): string {
  if (root === undefined) {
    let dir = dirname(fileURLToPath(import.meta.url));
    while (!existsSync(join(dir, "package.json"))) {
      const parent = dirname(dir);
      if (parent === dir) throw new Error("Atlas's repository root (package.json) not found");
      dir = parent;
    }
    root = dir;
  }
  return join(root, ...segments);
}
