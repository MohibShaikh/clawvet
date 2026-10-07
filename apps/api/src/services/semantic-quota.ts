import { and, eq, gte, sql, sum } from "drizzle-orm";
import { getCurrentPeriodStart } from "./tiers.js";

function limit(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid ${name}`);
  return value;
}

/** Reserve before provider work; failed attempts still consume budget. All API
 * replicas serialize reservations in PostgreSQL, not per-process memory. */
export async function reserveSemanticScan(userId: string, planLimit: number): Promise<boolean> {
  const { db, schema } = await import("../db/index.js");
  const period = getCurrentPeriodStart();
  const accountLimit = Math.min(planLimit, limit("CLAWVET_SEMANTIC_ACCOUNT_MONTHLY_LIMIT", 100));
  const globalLimit = limit("CLAWVET_SEMANTIC_GLOBAL_MONTHLY_LIMIT", 1000);
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(73482619)`);
    const [global] = await tx.select({ count: sum(schema.semanticUsage.scanCount) })
      .from(schema.semanticUsage).where(gte(schema.semanticUsage.periodStart, period));
    const rows = await tx.select().from(schema.semanticUsage).where(and(
      eq(schema.semanticUsage.userId, userId), eq(schema.semanticUsage.periodStart, period),
    ));
    const used = rows.reduce((total, row) => total + row.scanCount, 0);
    if (used >= accountLimit || Number(global?.count ?? 0) >= globalLimit) return false;
    if (rows.length) {
      await tx.update(schema.semanticUsage).set({ scanCount: rows[0].scanCount + 1 })
        .where(eq(schema.semanticUsage.id, rows[0].id));
    } else {
      await tx.insert(schema.semanticUsage).values({ userId, periodStart: period, scanCount: 1 });
    }
    return true;
  });
}
