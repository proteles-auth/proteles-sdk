import { createAuthMiddleware } from "@proteles/next";

// Protect everything except the home page and the auth routes. An
// unauthenticated request to a protected route is redirected to
// `/api/auth/login?returnTo=…`.
//
// `proxy.ts` is Next 16's name for what Next 14 and 15 call `middleware.ts`;
// the function is the same, and so is the default export. On Next 14 or 15,
// name this file `middleware.ts`.
//
// For the simplest zero-config setup (protect *everything* but the auth
// routes), you can instead write:
//   export { authMiddleware as proxy } from "@proteles/next";
const proxy = createAuthMiddleware(undefined, { publicPaths: ["/"] });
export default proxy;

export const config = {
  // Run on everything except Next internals and static files.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
