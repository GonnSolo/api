import { Elysia } from "elysia";
import { requireAuth } from "./middleware";
import { logAuditAction, getAuditLogs } from "../audit";

export const usersDomain = new Elysia({ prefix: '/users' })
  .use(requireAuth)

  // ── GET /users/profile ────────────────────────────────────
  .get('/profile', async ({ user, requestId }) => {
    await logAuditAction(requestId as string, user.id, 'access_profile', '/users/profile');
    return { profile: { id: user.id, role: user.role } };
  })

  // ── GET /users/admin ──────────────────────────────────────
  .get('/admin', async ({ user, requestId, set }) => {
    if (user.role !== 'admin') {
      await logAuditAction(requestId as string, user.id, 'unauthorized_access_attempt', '/users/admin');
      set.status = 403;
      return { error: 'Forbidden: Admins only' };
    }
    await logAuditAction(requestId as string, user.id, 'access_admin_panel', '/users/admin');
    return { data: 'Secret admin data' };
  })

  // ── GET /users/audit-logs ─────────────────────────────────
  .get('/audit-logs', async ({ user, requestId, query, set }) => {
    if (user.role !== 'admin') {
      await logAuditAction(requestId as string, user.id, 'unauthorized_access_attempt', '/users/audit-logs');
      set.status = 403;
      return { error: 'Forbidden: Admins only' };
    }
    const limit = query.limit ? Number(query.limit) : 50;
    const filterUserId = query.userId as string | undefined;
    const logs = await getAuditLogs(filterUserId, limit);
    await logAuditAction(requestId as string, user.id, 'access_audit_logs', '/users/audit-logs');
    return { logs };
  });
