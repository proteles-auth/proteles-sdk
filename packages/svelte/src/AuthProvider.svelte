<!--
  Wrap your app once (usually in `+layout.svelte`). Creates the auth store,
  puts it in context for every descendant, and revalidates against
  /api/auth/me on mount — so a stale `initialUser` (e.g. after a logout in
  another tab) self-corrects.

  Pass `initialUser` from a server `load` (see `@proteles/svelte/server`'s
  `getUser`) to avoid a signed-out flash on first paint.
-->
<script>
  import { onDestroy, onMount } from "svelte";
  import { createStoppableAuthStore } from "./store.js";
  import { setAuthContext } from "./context.js";

  /** BFF mount path. Defaults to PUBLIC_PROTELES_BASE_PATH or /api/auth. */
  export let basePath = undefined;
  /** Server-known user: undefined = unknown, null = signed out, object = signed in. */
  export let initialUser = undefined;

  const { store, stop } = createStoppableAuthStore({ basePath, initialUser });
  const auth = setAuthContext(store);

  onMount(() => {
    // Always revalidate on the client; never during SSR.
    void auth.reload();
  });
  // Stop asking a busy `/me` once the provider is gone. On the server this
  // runs after the render, when nothing has been asked.
  onDestroy(stop);
</script>

<slot />
