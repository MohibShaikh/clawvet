import { Queue } from "bullmq";
const redisUrl = new URL(process.env.REDIS_URL || "redis://localhost:6379");

const connection = {
  host: redisUrl.hostname,
  port: Number(redisUrl.port || 6379),
  password: redisUrl.password || undefined,
  db: redisUrl.pathname ? Number(redisUrl.pathname.replace("/", "") || 0) : 0,
  maxRetriesPerRequest: null,
};

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
