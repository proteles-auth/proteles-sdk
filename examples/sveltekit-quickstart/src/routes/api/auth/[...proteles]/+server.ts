// The entire OAuth flow (login, callback, logout, me) is handled here. Both
// verbs delegate to the same router; configuration comes from PROTELES_* env.
import { createAuthHandlers } from "@proteles/svelte/server";

export const { GET, POST } = createAuthHandlers();
