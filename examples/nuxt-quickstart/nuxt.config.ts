export default defineNuxtConfig({
  // The @proteles/* packages ship pre-built ESM in `dist/`, so no transpilation
  // is needed. Runtime config is read from PROTELES_* env vars by the server
  // handlers themselves — nothing to declare here.
  devtools: { enabled: false },
  // The tab read "localhost:3000"; every other quickstart names itself.
  app: { head: { title: "Proteles Nuxt quickstart" } },
});
