import { db } from "../../infrastructure/db";
import { auditLogs } from "../../infrastructure/db/schema";
import { logger } from "../../infrastructure/logger";
import { desc, eq } from "drizzle-orm";

export const logAuditAction = async (
  requestId: string | undefined | null,
  userId: string | null,
  action: string,
  resource: string,
  metadata?: string
) => {
  const reqId = requestId || crypto.randomUUID();
  try {
    await db.insert(auditLogs).values({
      id: crypto.randomUUID(),
      requestId: reqId,
      userId,
      action,
      resource,
      metadata,
    });
    logger.info({ requestId, userId, action, resource }, "Audit event recorded successfully");
  } catch (error) {
    logger.error({ requestId, action, error }, "Failed to record audit event");
  }
};

export const getAuditLogs = async (userId?: string, limit = 50) => {
  if (userId) {
    return db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.userId, userId))
      .orderBy(desc(auditLogs.createdAt))
      .limit(limit)
      .all();
  }
  return db
    .select()
    .from(auditLogs)
    .orderBy(desc(auditLogs.createdAt))
    .limit(limit)
    .all();
};
