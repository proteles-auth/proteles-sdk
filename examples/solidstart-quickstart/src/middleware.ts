// Attaches the current user to the event for every request, and guards every
// route except the home page and the auth routes. An unauthenticated request to
// a protected route is redirected to `/api/auth/login?returnTo=…`.
//
// `publicPaths: ["/"]` matches the home page *exactly* — it does not make the
// whole app public.
import { createMiddleware } from "@solidjs/start/middleware";
import { attachUser, guardRequest } from "@proteles/solid/server";

export default createMiddleware({
  onRequest: [
    async (event) => {
      await attachUser(event);
      return guardRequest(event, { publicPaths: ["/"] });
    },
  ],
});
