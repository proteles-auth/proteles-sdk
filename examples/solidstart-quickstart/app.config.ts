import { defineConfig } from "@solidjs/start/config";

export default defineConfig({
  // Registers src/middleware.ts, which attaches the user and guards routes.
  middleware: "./src/middleware.ts",
  vite: {
    resolve: {
      // One copy of Solid in the browser bundle. The `file:` link to
      // @proteles/solid resolves to packages/solid, whose own `solid-js`
      // import finds the SDK workspace's copy; the production build then ships
      // two runtimes, AuthProvider sets its context in one, the routes read the
      // other, and the page goes blank with "useAuth() must be called inside an
      // <AuthProvider>". The dev server was never affected: its dependency
      // pre-bundling already collapses the two. Installed from npm, solid-js
      // is a peer dependency of @proteles/solid and resolves to the app's own
      // copy, so the setting only matters for a linked SDK like this one.
      dedupe: ["solid-js", "solid-js/web", "solid-js/store"],
    },
  },
});
