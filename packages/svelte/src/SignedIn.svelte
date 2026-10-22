<!-- Renders its children only when a user is signed in (and loading is done). -->
<script>
  import { getAuth } from "./context.js";
  const auth = getAuth();
</script>

{#if $auth.isAuthenticated && !$auth.isLoading}<slot />{/if}
