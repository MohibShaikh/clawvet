import type { FastifyReply, FastifyRequest } from "fastify";
import { resolveUser, type ResolvedUser } from "./resolve-user.js";

declare module "fastify" {
  interface FastifyRequest {
    authUser?: ResolvedUser;
  }
}

/**
 * Fastify preHandler that enforces authentication. Rejects with 401 unless a
 * valid session cookie or `Bearer cg_…` API key resolves to a user, then
 * attaches it to `request.authUser` for the handler.
 *
 * Use as `{ preHandler: requireAuth }` on any protected route so a route is
 * either explicitly guarded or explicitly public — never unguarded by omission.
 */
export async function requireAuth(request: FastifyRequest, reply: FastifyReply) {
  const user = await resolveUser(request);
  if (!user) {
    return reply.status(401).send({ error: "Authentication required" });
  }
  request.authUser = user;
}
