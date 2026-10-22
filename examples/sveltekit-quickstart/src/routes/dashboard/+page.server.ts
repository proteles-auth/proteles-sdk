// This route is protected by `hooks.server.ts`: an unauthenticated request is
// redirected to `/api/auth/login` before it ever renders. Because the guard runs
// in the hook, we can safely read the user here.
import type { PageServerLoad } from "./$types";

export const load: PageServerLoad = async ({ locals }) => ({
  user: locals.protelesUser,
});
