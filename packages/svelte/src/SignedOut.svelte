<!-- Renders its children only when no user is signed in (and loading is done). -->
<script>
  import { getAuth } from "./context.js";
  const auth = getAuth();
</script>

{#if !$auth.isAuthenticated && !$auth.isLoading}<slot />{/if}
