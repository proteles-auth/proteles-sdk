import { sveltekit } from "@sveltejs/kit/vite";
import { loadEnv } from "vite";

export default ({ mode }) => {
  // @proteles/svelte reads PROTELES_* from process.env. Vite loads `.env` only
  // into import.meta.env and SvelteKit's `$env` modules, so without this the
  // `.env` the README has you write is never seen by `npm run dev` or
  // `npm run preview`. A variable already set in the real environment wins.
  // In production, set real environment variables instead (with adapter-node:
  // `node --env-file=.env build`).
  for (const [key, value] of Object.entries(loadEnv(mode, process.cwd(), "PROTELES_"))) {
    process.env[key] ??= value;
  }
  return { plugins: [sveltekit()] };
};
