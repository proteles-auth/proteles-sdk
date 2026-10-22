//! The no-build entry point. Bundled to a standalone IIFE that assigns
//! `window.protelesAuth`, so a page can load it from a CDN with a plain
//! `<script src>` and no tooling at all — which is how most Alpine apps are
//! built.
//!
//! It also self-registers on `alpine:init` when Alpine is present, so the
//! simplest possible page needs no inline script; pass options by setting
//! `window.protelesAuthOptions` before the bundle loads.

import { protelesAuth } from "./plugin.js";
import type { ProtelesAuthOptions } from "./types.js";

declare global {
  interface Window {
    protelesAuth?: typeof protelesAuth;
    protelesAuthOptions?: ProtelesAuthOptions;
    Alpine?: { plugin: (p: unknown) => void };
  }
}

if (typeof window !== "undefined") {
  window.protelesAuth = protelesAuth;

  // Convenience auto-registration. Alpine fires `alpine:init` before it starts,
  // which is exactly when plugins must be added. Explicitly calling
  // `Alpine.plugin(protelesAuth({...}))` yourself still works — registering the
  // same store name twice is what Alpine would warn about, so we only auto-wire
  // when the page hasn't opted out.
  document.addEventListener("alpine:init", () => {
    if (window.protelesAuthOptions === null) return; // explicit opt-out
    window.Alpine?.plugin(protelesAuth(window.protelesAuthOptions ?? {}));
  });
}

export { protelesAuth };
