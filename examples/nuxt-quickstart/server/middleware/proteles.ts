// Puts the current user on `event.context.protelesUser` for every request, and
// guards every route except the home page and the auth routes. An
// unauthenticated request to a protected route is redirected to
// `/api/auth/login?returnTo=…`.
//
// `publicPaths: ["/"]` matches the home page *exactly* — it does not make the
// whole app public.
import { CONTEXT_USER_KEY, getUser, guardRequest } from "@proteles/vue/server";

export default defineEventHandler(async (event) => {
  event.context[CONTEXT_USER_KEY] = await getUser(event);
  const redirect = await guardRequest(event, { publicPaths: ["/"] });
  if (redirect) return redirect;
});
