<script>
  import { SignOutButton } from "@proteles/svelte";

  export let data;
</script>

<h1>Dashboard</h1>
<p>Signed in as <strong>{data.user?.email ?? data.user?.sub}</strong>.</p>
<p>This page is only reachable when authenticated.</p>
<SignOutButton>Sign out</SignOutButton>
<p><a href="/">← Home</a></p>
