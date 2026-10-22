<!-- A button that starts sign-up — or sign-in, where the workspace has not
     opened its sign-up page. -->
<script>
  import { getAuth } from "./context.js";
  const auth = getAuth();

  /** Path to return to after signing up. Defaults to the current path. */
  export let returnTo = undefined;
  let className = "";
  export { className as class };
</script>

<button type="button" class={className} on:click={() => auth.signUp({ returnTo })}>
  <slot>Sign up</slot>
</button>
