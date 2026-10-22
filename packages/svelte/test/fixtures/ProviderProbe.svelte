<!--
  Test fixture: the real <AuthProvider>, with a child that hands the provider's
  own store to the test, so what the provider does to its store can be seen.
-->
<script>
  import AuthProvider from "../../src/AuthProvider.svelte";
  import Capture from "./Capture.svelte";

  export let basePath;
  export let capture;
</script>

<AuthProvider {basePath}><Capture {capture} /></AuthProvider>
