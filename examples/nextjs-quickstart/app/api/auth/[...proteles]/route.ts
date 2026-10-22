// The entire OAuth flow (login, callback, logout, me) is handled here. Both
// verbs delegate to the same BFF router; configuration comes from PROTELES_* env.
import { createAuthHandlers } from "@proteles/next";

export const { GET, POST } = createAuthHandlers();
