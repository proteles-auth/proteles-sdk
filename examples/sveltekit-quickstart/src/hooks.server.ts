// Puts the current user on `event.locals.protelesUser` for every request, and
// guards every route except the home page and the auth routes. An
// unauthenticated request to a protected route is redirected to
// `/api/auth/login?returnTo=…`.
//
// `publicPaths: ["/"]` matches the home page *exactly* — it does not make the
// whole app public.
import { createAuthHandle } from "@proteles/svelte/server";

export const handle = createAuthHandle(undefined, { publicPaths: ["/"] });
