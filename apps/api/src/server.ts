import Fastify from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import { scanRoutes } from "./routes/scans.js";
import { skillRoutes } from "./routes/skills.js";
import { authRoutes } from "./routes/auth.js";
import { webhookRoutes } from "./routes/webhooks.js";

const app = Fastify({
  logger: true,
  trustProxy: true,
  bodyLimit: 1_048_576, // 1MB
});

// Credentialed CORS must never reflect arbitrary origins. Default to the web
// app's origin; CORS_ORIGIN can supply a comma-separated allowlist.
const corsOrigin = (process.env.CORS_ORIGIN || process.env.WEB_URL || "http://localhost:3000")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

await app.register(cors, {
  origin: corsOrigin,
  credentials: true,
});

await app.register(rateLimit, {
  max: parseInt(process.env.RATE_LIMIT_MAX || "100"),
  timeWindow: "1 minute",
});

await app.register(scanRoutes);
await app.register(skillRoutes);
await app.register(authRoutes);
await app.register(webhookRoutes);

app.get("/healthz", async () => ({ status: "ok", timestamp: new Date().toISOString() }));

app.get("/readyz", async (request, reply) => {
  try {
    const { db } = await import("./db/index.js");
    await db.execute({ sql: "SELECT 1", params: [] } as any);
    return { status: "ready", db: true };
  } catch {
    return { status: "ready", db: false };
  }
});

const port = parseInt(process.env.PORT || "3001");

async function shutdown(signal: string) {
  app.log.info(`Received ${signal}, shutting down gracefully...`);
  await app.close();
  process.exit(0);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

try {
  await app.listen({ port, host: "0.0.0.0" });
  console.log(`ClawVet API running on http://localhost:${port}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
