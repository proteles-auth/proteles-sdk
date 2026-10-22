// Installs the Vue plugin with the user the server already knows about, so the
// first paint reflects real auth state (no signed-out flash). The plugin still
// revalidates against /api/auth/me on mount.
//
// The user comes from `server/middleware/proteles.ts`, which read it from the
// session cookie without refreshing anything. Fetching /api/auth/me during
// server rendering instead would refresh an expired access token, and Nuxt does
// not pass the rotated cookie from that internal request on to the browser —
// which keeps the spent refresh token and is signed out by the next refresh.
import { protelesAuth } from "@proteles/vue";

type InitialUser = { user: Record<string, unknown> | null; known: boolean };

export default defineNuxtPlugin(async (nuxtApp) => {
  // Set on the server, carried to the browser in the payload.
  const initial = useState<InitialUser | null>("proteles-initial-user", () => null);
  if (import.meta.server) {
    const { CONTEXT_USER_KEY } = await import("@proteles/vue/server");
    const { cookieNames } = await import("@proteles/bff");
    const user = (useRequestEvent()?.context[CONTEXT_USER_KEY] as InitialUser["user"] | undefined) ?? null;
    // No user but a session cookie: an expired access token (or a dead
    // session) that only /api/auth/me can settle. Render "loading" rather than
    // "signed out" until it has. The name follows PROTELES_COOKIE_SECURE, as the
    // server middleware's own configuration does.
    initial.value = { user, known: user !== null || !useCookie(cookieNames().session).value };
  }
  nuxtApp.vueApp.use(protelesAuth({ initialUser: initial.value?.known ? (initial.value.user as never) : undefined }));
});
