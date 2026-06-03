import { Elysia, status } from "elysia";
import { jwt } from "@elysiajs/jwt";

export const requireAuth = new Elysia({ name: 'requireAuth' })
  .use(
    jwt({
      name: 'jwt',
      secret: process.env.JWT_SECRET || 'super-secret',
    })
  )
  .derive({ as: 'scoped' }, async ({ cookie: { auth_token }, jwt }) => {
    if (!auth_token.value) {
      return status(401, { error: "Unauthorized" });
    }
    const user = await jwt.verify(auth_token.value) as { id: string; role: string } | false;
    if (!user) {
      return status(401, { error: "Unauthorized" });
    }
    return { user };
  });
