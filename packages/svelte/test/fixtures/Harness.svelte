<!--
  Test fixture: puts a caller-supplied auth store in context and renders every
  component at once, so one SSR render exercises context wiring plus each
  component's conditional logic for a given auth state.
-->
<script>
  import { setAuthContext } from "../../src/context.js";
  import SignedIn from "../../src/SignedIn.svelte";
  import SignedOut from "../../src/SignedOut.svelte";
  import Protect from "../../src/Protect.svelte";
  import SignInButton from "../../src/SignInButton.svelte";
  import SignOutButton from "../../src/SignOutButton.svelte";
  import SignUpButton from "../../src/SignUpButton.svelte";
  import UserButton from "../../src/UserButton.svelte";

  export let store;
  setAuthContext(store);
</script>

<SignedIn><span data-t="in">IN</span></SignedIn>
<SignedOut><span data-t="out">OUT</span></SignedOut>
<Protect>
  <span data-t="allow">ALLOW</span>
  <span slot="fallback" data-t="deny">DENY</span>
</Protect>
<SignInButton class="cta">Continue</SignInButton>
<SignUpButton class="join" />
<SignOutButton />
<UserButton class="chip" />
