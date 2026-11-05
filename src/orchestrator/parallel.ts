// Runs independent jobs (compiler processes, mostly) as many at a time as the machine has cores.
import { availableParallelism } from "node:os";

export async function forEachConcurrently<T>(items: readonly T[], job: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const item = items[next++] as T;
      await job(item);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(availableParallelism(), items.length)) }, worker));
}
