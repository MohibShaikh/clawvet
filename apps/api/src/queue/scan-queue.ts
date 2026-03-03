import { Queue } from "bullmq";
import IORedis from "ioredis";

const connection = new IORedis(process.env.REDIS_URL || "redis://localhost:6379", {
  maxRetriesPerRequest: null,
});

export const scanQueue = new Queue("scans", { connection });

export async function enqueueScan(data: {
  scanId: string;
  content: string;
  semantic?: boolean;
}) {
  return scanQueue.add("scan-skill", data, {
    attempts: 3,
    backoff: { type: "exponential", delay: 1000 },
  });
}
