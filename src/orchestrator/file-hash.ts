// The SHA-256 of a file, streamed: a game's executable can exceed what one read returns (2 GiB). It identifies a
// binary in the graph (bin_ and fn_ IDs derive from it).
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";

export async function fileSha256(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}
