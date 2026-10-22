<!--
  Gates content behind authentication. Shows the `fallback` slot when signed
  out, and nothing at all until who is signed in is known (see `isLoading`).
-->
<script>
  import { getAuth } from "./context.js";
  const auth = getAuth();
</script>

{#if !$auth.isLoading}
  {#if $auth.isAuthenticated}
    <slot />
  {:else}
    <slot name="fallback" />
  {/if}
{/if}
