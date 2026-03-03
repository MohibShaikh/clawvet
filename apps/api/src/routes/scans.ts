import type { FastifyInstance } from "fastify";
import { scanSkill } from "../services/scanner.js";
import { eq, desc } from "drizzle-orm";

interface ScanBody {
  content: string;
  semantic?: boolean;
  skillName?: string;
}

export async function scanRoutes(app: FastifyInstance) {
  // Submit a skill for scanning
  app.post<{ Body: ScanBody }>("/api/v1/scans", async (request, reply) => {
    const { content, semantic, skillName } = request.body;

    if (!content) {
      return reply.status(400).send({ error: "content is required" });
    }

    const result = await scanSkill(content, { semantic });
    if (skillName) {
      result.skillName = skillName;
    }

    // Try to persist to DB if available
    try {
      const { db, schema } = await import("../db/index.js");
      const [scan] = await db
        .insert(schema.scans)
        .values({
          skillName: result.skillName,
          skillVersion: result.skillVersion || null,
          skillSource: result.skillSource,
          status: "complete",
          riskScore: result.riskScore,
          riskGrade: result.riskGrade,
          findingsCount: result.findingsCount,
          completedAt: new Date(),
        })
        .returning();

      result.id = scan.id;

      // Insert findings
      if (result.findings.length > 0) {
        await db.insert(schema.findings).values(
          result.findings.map((f) => ({
            scanId: scan.id,
            category: f.category,
            severity: f.severity,
            title: f.title,
            description: f.description,
            evidence: f.evidence || null,
            lineNumber: f.lineNumber ?? null,
            analysisPass: f.analysisPass,
          }))
        );
      }
    } catch {
      // DB not available — return result without persistence
    }

    return reply.status(200).send(result);
  });

  // Get scan result by ID
  app.get<{ Params: { id: string } }>(
    "/api/v1/scans/:id",
    async (request, reply) => {
      try {
        const { db, schema } = await import("../db/index.js");
        const scan = await db.query.scans.findFirst({
          where: eq(schema.scans.id, request.params.id),
        });

        if (!scan) {
          return reply.status(404).send({ error: "Scan not found" });
        }

        const scanFindings = await db.query.findings.findMany({
          where: eq(schema.findings.scanId, scan.id),
        });

        return reply.send({
          ...scan,
          findings: scanFindings.map((f) => ({
            category: f.category,
            severity: f.severity,
            title: f.title,
            description: f.description,
            evidence: f.evidence,
            lineNumber: f.lineNumber,
            analysisPass: f.analysisPass,
          })),
        });
      } catch {
        return reply
          .status(503)
          .send({ error: "Database not available" });
      }
    }
  );

  // List scans (paginated)
  app.get<{ Querystring: { limit?: string; offset?: string } }>(
    "/api/v1/scans",
    async (request, reply) => {
      try {
        const { db, schema } = await import("../db/index.js");
        const limit = Math.min(parseInt(request.query.limit || "20"), 100);
        const offset = parseInt(request.query.offset || "0");

        const results = await db.query.scans.findMany({
          orderBy: desc(schema.scans.createdAt),
          limit,
          offset,
        });

        return reply.send({ scans: results, limit, offset });
      } catch {
        return reply
          .status(503)
          .send({ error: "Database not available" });
      }
    }
  );

  // Public stats
  app.get("/api/v1/stats", async (request, reply) => {
    try {
      const { db, schema } = await import("../db/index.js");
      const { count, sum, avg } = await import("drizzle-orm");

      const [stats] = await db
        .select({
          skillsScanned: count(schema.scans.id),
          avgRiskScore: avg(schema.scans.riskScore),
        })
        .from(schema.scans)
        .where(eq(schema.scans.status, "complete"));

      const [threatStats] = await db
        .select({ threatsFound: count(schema.findings.id) })
        .from(schema.findings);

      return reply.send({
        skillsScanned: Number(stats.skillsScanned),
        threatsFound: Number(threatStats.threatsFound),
        avgRiskScore: Math.round(Number(stats.avgRiskScore) || 0),
      });
    } catch {
      return reply.send({
        skillsScanned: 0,
        threatsFound: 0,
        avgRiskScore: 0,
      });
    }
  });
}
