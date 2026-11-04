// Where scripts/setup.sh installs the engines, so Atlas finds them with no configuration. Keep in step with the
// same computation in scripts/setup.sh.
import { homedir } from "node:os";
import { join } from "node:path";

export function toolsDir(env: NodeJS.ProcessEnv = process.env): string {
  if (env.ATLAS_TOOLS_DIR) return env.ATLAS_TOOLS_DIR;
  return join(env.XDG_DATA_HOME || join(homedir(), ".local", "share"), "atlas", "tools");
}
