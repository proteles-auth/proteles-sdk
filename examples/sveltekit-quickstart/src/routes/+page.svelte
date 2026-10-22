<script>
  import { SignedIn, SignedOut, SignInButton, UserButton, getAuth } from "@proteles/svelte";

  const auth = getAuth();
</script>

<h1>Proteles SvelteKit quickstart</h1>
<p>A SvelteKit app with authentication in three files. See the README.</p>

{#if $auth.isLoading}
  <p>Loading…</p>
{:else}
  <SignedOut>
    <p>You are signed out.</p>
    <SignInButton>Sign in</SignInButton>
  </SignedOut>

  <SignedIn>
    <p>Hi <strong>{$auth.user?.email ?? $auth.user?.preferredUsername ?? $auth.user?.sub}</strong> 👋</p>
    <UserButton />
    <p><a href="/dashboard">Visit the protected dashboard →</a></p>
  </SignedIn>
{/if}
