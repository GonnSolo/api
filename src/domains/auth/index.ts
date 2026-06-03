import { Elysia, t } from "elysia";
import { jwt } from "@elysiajs/jwt";
import { db } from "../../infrastructure/db";
import { users, oauthAccounts, refreshTokens } from "../../infrastructure/db/schema";
import { eq, and, gt, isNull } from "drizzle-orm";
import { logger } from "../../infrastructure/logger";
import { logAuditAction } from "../audit";

// --- Refresh Token Helpers ---

const REFRESH_TOKEN_EXPIRES_DAYS = 30;
const ACCESS_TOKEN_EXPIRES_SECS = 15 * 60; // 15 minutes

async function hashToken(token: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createRefreshToken(userId: string): Promise<string> {
  const rawToken = crypto.randomUUID() + '-' + crypto.randomUUID();
  const tokenHash = await hashToken(rawToken);
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_EXPIRES_DAYS);

  await db.insert(refreshTokens).values({
    id: crypto.randomUUID(),
    userId,
    tokenHash,
    expiresAt,
  });

  return rawToken;
}

async function rotateRefreshToken(rawToken: string, userId: string): Promise<string | null> {
  const tokenHash = await hashToken(rawToken);
  const now = new Date();

  const existing = await db
    .select()
    .from(refreshTokens)
    .where(
      and(
        eq(refreshTokens.tokenHash, tokenHash),
        eq(refreshTokens.userId, userId),
        isNull(refreshTokens.revokedAt),
        gt(refreshTokens.expiresAt, now)
      )
    )
    .get();

  if (!existing) return null;

  // Revoke the old token
  await db
    .update(refreshTokens)
    .set({ revokedAt: now })
    .where(eq(refreshTokens.id, existing.id));

  // Issue a new one
  return createRefreshToken(userId);
}

async function revokeRefreshToken(rawToken: string): Promise<void> {
  const tokenHash = await hashToken(rawToken);
  await db
    .update(refreshTokens)
    .set({ revokedAt: new Date() })
    .where(eq(refreshTokens.tokenHash, tokenHash));
}

// --- OAuth Helper ---

async function findOrCreateOAuthUser(
  provider: string,
  providerAccountId: string,
  email: string
): Promise<typeof users.$inferSelect> {
  let oauthAcc = await db
    .select()
    .from(oauthAccounts)
    .where(
      and(
        eq(oauthAccounts.provider, provider),
        eq(oauthAccounts.providerAccountId, providerAccountId)
      )
    )
    .get();

  let user: typeof users.$inferSelect | undefined;

  if (!oauthAcc) {
    user = await db.select().from(users).where(eq(users.email, email)).get();
    if (!user) {
      user = await db
        .insert(users)
        .values({ id: crypto.randomUUID(), email, role: 'user' })
        .returning()
        .get();
    }
    await db.insert(oauthAccounts).values({
      id: crypto.randomUUID(),
      userId: user.id,
      provider,
      providerAccountId,
    });
    logger.info({ userId: user.id, provider, action: 'oauth_link' }, `Linked ${provider} account`);
  } else {
    user = await db.select().from(users).where(eq(users.id, oauthAcc.userId)).get();
  }

  if (!user) throw new Error('Failed to find or create user');
  return user;
}

// --- Auth Domain ---

export const authDomain = new Elysia({ prefix: '/auth' })
  .use(
    jwt({
      name: 'jwt',
      secret: process.env.JWT_SECRET || 'super-secret',
    })
  )

  // ── Register ──────────────────────────────────────────────
  .post(
    '/register',
    async ({ body, set, requestId }) => {
      const { email, password } = body;
      const existingUser = await db.select().from(users).where(eq(users.email, email)).get();
      if (existingUser) {
        set.status = 400;
        return { error: 'User already exists' };
      }

      const passwordHash = await Bun.password.hash(password);
      const newUser = await db
        .insert(users)
        .values({ id: crypto.randomUUID(), email, passwordHash, role: 'user' })
        .returning()
        .get();

      await logAuditAction(requestId as string, newUser.id, 'register', '/auth/register');
      logger.info({ userId: newUser.id, action: 'register' }, 'User registered');

      return { success: true, userId: newUser.id };
    },
    {
      body: t.Object({
        email: t.String({ format: 'email' }),
        password: t.String({ minLength: 6 }),
      }),
    }
  )

  // ── Login ─────────────────────────────────────────────────
  .post(
    '/login',
    async ({ body, jwt, cookie: { auth_token, refresh_token }, set, requestId }) => {
      const { email, password } = body;
      const user = await db.select().from(users).where(eq(users.email, email)).get();
      if (!user || !user.passwordHash) {
        set.status = 401;
        return { error: 'Invalid credentials' };
      }
      const isMatch = await Bun.password.verify(password, user.passwordHash);
      if (!isMatch) {
        await logAuditAction(requestId as string, user.id, 'login_failed', '/auth/login');
        set.status = 401;
        return { error: 'Invalid credentials' };
      }

      const token = await jwt.sign({ id: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_EXPIRES_SECS });
      auth_token.set({ value: token, httpOnly: true, maxAge: ACCESS_TOKEN_EXPIRES_SECS, path: '/' });

      const rawRefresh = await createRefreshToken(user.id);
      refresh_token.set({ value: rawRefresh, httpOnly: true, maxAge: REFRESH_TOKEN_EXPIRES_DAYS * 86400, path: '/auth/refresh' });

      await logAuditAction(requestId as string, user.id, 'login', '/auth/login');
      logger.info({ userId: user.id, action: 'login' }, 'User logged in');

      return { success: true, token };
    },
    {
      body: t.Object({
        email: t.String({ format: 'email' }),
        password: t.String(),
      }),
    }
  )

  // ── Refresh Token ─────────────────────────────────────────
  .post('/refresh', async ({ cookie: { refresh_token, auth_token }, jwt, set, requestId }) => {
    const rawToken = refresh_token.value;
    if (!rawToken) {
      set.status = 401;
      return { error: 'No refresh token provided' };
    }

    // We need the userId from the token hash — look up by hash
    const tokenHash = await hashToken(rawToken);
    const now = new Date();
    const existing = await db
      .select()
      .from(refreshTokens)
      .where(
        and(
          eq(refreshTokens.tokenHash, tokenHash),
          isNull(refreshTokens.revokedAt),
          gt(refreshTokens.expiresAt, now)
        )
      )
      .get();

    if (!existing) {
      set.status = 401;
      return { error: 'Invalid or expired refresh token' };
    }

    const user = await db.select().from(users).where(eq(users.id, existing.userId)).get();
    if (!user) {
      set.status = 401;
      return { error: 'User not found' };
    }

    const newRawRefresh = await rotateRefreshToken(rawToken, user.id);
    if (!newRawRefresh) {
      set.status = 401;
      return { error: 'Could not rotate refresh token' };
    }

    const newToken = await jwt.sign({ id: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_EXPIRES_SECS });
    auth_token.set({ value: newToken, httpOnly: true, maxAge: ACCESS_TOKEN_EXPIRES_SECS, path: '/' });
    refresh_token.set({ value: newRawRefresh, httpOnly: true, maxAge: REFRESH_TOKEN_EXPIRES_DAYS * 86400, path: '/auth/refresh' });

    await logAuditAction(requestId as string, user.id, 'token_refresh', '/auth/refresh');
    logger.info({ userId: user.id, action: 'token_refresh' }, 'Tokens refreshed');

    return { success: true, token: newToken };
  })

  // ── Logout ────────────────────────────────────────────────
  .post('/logout', async ({ cookie: { auth_token, refresh_token }, requestId }) => {
    if (refresh_token.value) {
      await revokeRefreshToken(refresh_token.value);
    }
    auth_token.set({ value: '', maxAge: 0, path: '/' });
    refresh_token.set({ value: '', maxAge: 0, path: '/auth/refresh' });

    await logAuditAction(requestId as string, null, 'logout', '/auth/logout');
    return { success: true };
  })

  // ── GitHub OAuth ──────────────────────────────────────────
  .get('/github', ({ set }) => {
    const clientId = process.env.GITHUB_CLIENT_ID || 'dummy_client_id';
    const redirectUri = process.env.GITHUB_REDIRECT_URI || 'http://localhost:3000/auth/github/callback';
    set.status = 302;
    set.redirect = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&scope=user:email`;
  })

  // Returns the GitHub OAuth redirect URL as JSON (useful for testing/debugging)
  .get('/github/redirect-url', ({ }) => {
    const clientId = process.env.GITHUB_CLIENT_ID || 'dummy_client_id';
    const redirectUri = process.env.GITHUB_REDIRECT_URI || 'http://localhost:3000/auth/github/callback';
    const url = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&scope=user:email`;
    return { provider: 'github', redirectUrl: url };
  })

  .get('/github/callback', async ({ query, jwt, cookie: { auth_token, refresh_token }, set, requestId }) => {
    const { code } = query as { code?: string };
    if (!code) {
      set.status = 400;
      return { error: 'No code provided' };
    }

    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
      }),
    }).then(res => res.json() as any);

    if (tokenRes.error) {
      set.status = 400;
      return { error: tokenRes.error_description || 'Failed to authenticate with GitHub' };
    }

    const accessToken = tokenRes.access_token;
    const [userRes, emailRes] = await Promise.all([
      fetch('https://api.github.com/user', { headers: { Authorization: `Bearer ${accessToken}` } }).then(r => r.json() as any),
      fetch('https://api.github.com/user/emails', { headers: { Authorization: `Bearer ${accessToken}` } }).then(r => r.json() as any),
    ]);

    const primaryEmailObj = Array.isArray(emailRes) ? emailRes.find((e: any) => e.primary) : null;
    const email = primaryEmailObj ? primaryEmailObj.email : userRes.email;
    if (!email) { set.status = 400; return { error: 'No email found from GitHub' }; }

    const user = await findOrCreateOAuthUser('github', String(userRes.id), email);
    const token = await jwt.sign({ id: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_EXPIRES_SECS });
    auth_token.set({ value: token, httpOnly: true, maxAge: ACCESS_TOKEN_EXPIRES_SECS, path: '/' });

    const rawRefresh = await createRefreshToken(user.id);
    refresh_token.set({ value: rawRefresh, httpOnly: true, maxAge: REFRESH_TOKEN_EXPIRES_DAYS * 86400, path: '/auth/refresh' });

    await logAuditAction(requestId as string, user.id, 'login_github', '/auth/github/callback');
    logger.info({ userId: user.id, action: 'login_github' }, 'User logged in via GitHub');

    return { success: true, token };
  })

  // ── Google OAuth ──────────────────────────────────────────
  .get('/google', ({ set }) => {
    const clientId = process.env.GOOGLE_CLIENT_ID || 'dummy_google_client_id';
    const redirectUri = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback';
    const scope = encodeURIComponent('openid email profile');
    set.status = 302;
    set.redirect = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${scope}&access_type=offline`;
  })

  // Returns the Google OAuth redirect URL as JSON (useful for testing/debugging)
  .get('/google/redirect-url', ({ }) => {
    const clientId = process.env.GOOGLE_CLIENT_ID || 'dummy_google_client_id';
    const redirectUri = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback';
    const scope = encodeURIComponent('openid email profile');
    const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${scope}&access_type=offline`;
    return { provider: 'google', redirectUrl: url };
  })

  .get('/google/callback', async ({ query, jwt, cookie: { auth_token, refresh_token }, set, requestId }) => {
    const { code } = query as { code?: string };
    if (!code) {
      set.status = 400;
      return { error: 'No code provided' };
    }

    const redirectUri = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback';
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID || '',
        client_secret: process.env.GOOGLE_CLIENT_SECRET || '',
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
    }).then(res => res.json() as any);

    if (tokenRes.error) {
      set.status = 400;
      return { error: tokenRes.error_description || 'Failed to authenticate with Google' };
    }

    const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokenRes.access_token}` },
    }).then(r => r.json() as any);

    const email = userInfoRes.email;
    const googleId = userInfoRes.sub;
    if (!email || !googleId) {
      set.status = 400;
      return { error: 'No email or ID found from Google' };
    }

    const user = await findOrCreateOAuthUser('google', String(googleId), email);
    const token = await jwt.sign({ id: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_EXPIRES_SECS });
    auth_token.set({ value: token, httpOnly: true, maxAge: ACCESS_TOKEN_EXPIRES_SECS, path: '/' });

    const rawRefresh = await createRefreshToken(user.id);
    refresh_token.set({ value: rawRefresh, httpOnly: true, maxAge: REFRESH_TOKEN_EXPIRES_DAYS * 86400, path: '/auth/refresh' });

    await logAuditAction(requestId as string, user.id, 'login_google', '/auth/google/callback');
    logger.info({ userId: user.id, action: 'login_google' }, 'User logged in via Google');

    return { success: true, token };
  });
