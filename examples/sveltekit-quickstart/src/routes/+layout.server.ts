// Read the user server-side (from the httpOnly cookie) so the very first paint
// already reflects the real auth state — no signed-out flash. `AuthProvider`
// still revalidates against /api/auth/me on mount.
import { getUser } from "@proteles/svelte/server";
import type { LayoutServerLoad } from "./$types";

export const load: LayoutServerLoad = async (event) => ({
  user: await getUser(event),
});
