<!-- A button that logs out. -->
<script>
  import { getAuth } from "./context.js";
  const auth = getAuth();

  /** Path to return to after logout. Defaults to "/". */
  export let returnTo = undefined;
  let className = "";
  export { className as class };
</script>

<button type="button" class={className} on:click={() => auth.signOut({ returnTo })}>
  <slot>Sign out</slot>
</button>
