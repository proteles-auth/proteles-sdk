<script>
  import { AuthProvider } from "@proteles/svelte";

  export let data;
</script>

<AuthProvider initialUser={data.user}>
  <main>
    <slot />
  </main>
</AuthProvider>

<style>
  main {
    font-family: system-ui, sans-serif;
    max-width: 640px;
    margin: 64px auto;
    padding: 0 16px;
  }
</style>
