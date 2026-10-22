<!--
  A compact identity chip: the user's name/email plus a sign-out control.
  Renders nothing when signed out. Unstyled by design — pass `class`.
-->
<script>
  import { getAuth } from "./context.js";
  const auth = getAuth();

  let className = "";
  export { className as class };

  $: user = $auth.user;
  $: label = user ? user.preferredUsername || user.email || user.sub : "";
</script>

{#if user}
  <span class={className} data-proteles="user-button">
    <span data-proteles="user-label">{label}</span>
    <button type="button" data-proteles="user-signout" on:click={() => auth.signOut()}>
      Sign out
    </button>
  </span>
{/if}
