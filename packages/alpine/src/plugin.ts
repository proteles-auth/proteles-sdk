//! The Alpine plugin: registers the auth store, the `$auth` magic, and the
//! `x-signed-in` / `x-signed-out` directives.
//!
//! Alpine has no component model, so this package's surface is deliberately
//! different from the React/Svelte/Vue/Solid ones: instead of `<SignedIn>`
//! components you get directives you put on any element.

import { createAuthStore } from "./store.js";
import type { AlpineLike, AuthStore, ProtelesAuthOptions } from "./types.js";

const DEFAULT_STORE_NAME = "proteles";
const DEFAULT_MAGIC_NAME = "auth";

/**
 * Creates the Alpine plugin.
 *
 * ```js
 * Alpine.plugin(protelesAuth());
 * Alpine.start();
 * ```
 *
 * Registers, in order:
 *   * `Alpine.store(storeName)` — the reactive auth state (`$store.proteles`);
 *   * a `$auth` magic property, so expressions read `$auth.user` rather than
 *     `$store.proteles.user`;
 *   * `x-signed-in` and `x-signed-out` directives.
 *
 * Returns the plugin function, with the store attached as `.store` for callers
 * who want a direct reference.
 */
export function protelesAuth(
  options: ProtelesAuthOptions = {},
): ((Alpine: AlpineLike) => void) & { store: AuthStore } {
  const storeName = options.storeName ?? DEFAULT_STORE_NAME;
  const magicName = options.magicName ?? DEFAULT_MAGIC_NAME;
  const store = createAuthStore(options);

  const plugin = (Alpine: AlpineLike): void => {
    Alpine.store(storeName, store);

    // Read the *registered* store rather than the raw object, so expressions get
    // Alpine's reactive proxy and re-evaluate when state changes.
    const reactiveStore = (): AuthStore => (Alpine.store(storeName) as AuthStore) ?? store;

    Alpine.magic(magicName, () => reactiveStore());

    Alpine.directive("signed-in", (el, _directive, { effect }) => {
      applyVisibility(el, effect, () => {
        const s = reactiveStore();
        return s.isAuthenticated && !s.isLoading;
      });
    });

    Alpine.directive("signed-out", (el, _directive, { effect }) => {
      applyVisibility(el, effect, () => {
        const s = reactiveStore();
        return !s.isAuthenticated && !s.isLoading;
      });
    });
  };

  return Object.assign(plugin, { store });
}

/**
 * Toggles an element the way `x-show` does, but hides it *immediately* on setup
 * rather than after the first effect run.
 *
 * That ordering is the whole point of these directives: while the first
 * `/api/auth/me` is in flight neither state is known, so an element that starts
 * visible would flash the wrong UI — signed-out content to a signed-in user, or
 * vice versa. Both directives stay hidden until the state is actually known.
 */
function applyVisibility(el: HTMLElement, effect: (fn: () => void) => void, shouldShow: () => boolean): void {
  const previousDisplay = el.style.display;
  el.style.display = "none";
  effect(() => {
    el.style.display = shouldShow() ? (previousDisplay === "none" ? "" : previousDisplay) : "none";
  });
}
