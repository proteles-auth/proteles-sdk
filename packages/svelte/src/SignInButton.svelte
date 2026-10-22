<!-- A button that starts the login flow. -->
<script>
  import { getAuth } from "./context.js";
  const auth = getAuth();

  /** Path to return to after login. Defaults to the current path. */
  export let returnTo = undefined;
  /** Force a social connection, e.g. "google". */
  export let connection = undefined;
  let className = "";
  export { className as class };
</script>

<button type="button" class={className} on:click={() => auth.signIn({ returnTo, connection })}>
  <slot>Sign in</slot>
</button>
