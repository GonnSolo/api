import { Elysia } from "elysia";
import { swagger } from "@elysiajs/swagger";
import { cors } from "@elysiajs/cors";
import { logger } from "./infrastructure/logger";
import { authDomain } from "./domains/auth";
import { usersDomain } from "./domains/users";
import { db } from "./infrastructure/db";
import { sql } from "drizzle-orm";

// Auto-create tables on startup (SQLite pragmas + DDL)
async function runMigrations() {
  try {
    db.run(sql`PRAGMA journal_mode=WAL`);
    db.run(sql`PRAGMA foreign_keys=ON`);

    db.run(sql`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT,
        role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
        created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
        updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
      )
    `);

    db.run(sql`
      CREATE TABLE IF NOT EXISTS oauth_accounts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        provider_account_id TEXT NOT NULL,
        created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
      )
    `);

    db.run(sql`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        user_id TEXT,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        metadata TEXT,
        created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
      )
    `);

    db.run(sql`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER,
        created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
      )
    `);

    logger.info('Database migrations applied successfully');
  } catch (err) {
    logger.error({ err }, 'Failed to run migrations');
    process.exit(1);
  }
}

await runMigrations();

const app = new Elysia()
  .use(cors())
  .use(
    swagger({
      documentation: {
        info: {
          title: 'Secure API — AAA + OAuth 2.0',
          version: '2.0.0',
          description: 'API con autenticación JWT, Refresh Tokens, RBAC, OAuth 2.0 (GitHub + Google) y auditoría',
        },
        tags: [
          { name: 'auth', description: 'Autenticación y gestión de sesión' },
          { name: 'users', description: 'Recursos protegidos de usuario' },
        ],
      },
    })
  )
  .derive(() => ({
    requestId: crypto.randomUUID(),
  }))
  .onRequest(({ request, requestId }) => {
    logger.info({ requestId, method: request.method, url: request.url }, 'Incoming request');
  })
  .onAfterHandle(({ request, set, requestId }) => {
    logger.info({ requestId, method: request.method, url: request.url, status: set.status }, 'Request completed');
  })
  .onError(({ code, error, requestId }) => {
    logger.error({ requestId, code, error: error.message }, 'Request error');
  })
  .use(authDomain)
  .use(usersDomain)
  .get('/', () => ({ message: 'Secure API v2.0 — AAA + OAuth 2.0', docs: '/swagger' }))
  .listen(3000);

logger.info(`🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`);

export type App = typeof app;
