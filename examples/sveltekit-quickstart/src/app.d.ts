import type { PublicUser } from "@proteles/svelte/server";

declare global {
  namespace App {
    interface Locals {
      /** Set by `createAuthHandle` in `hooks.server.ts`. */
      protelesUser: PublicUser | null;
    }
  }
}

export {};
