//! A stub of the slice of Alpine this plugin uses.
//!
//! Real Alpine can't be loaded here at all — it touches `MutationObserver` at
//! module scope, so `import "alpinejs"` throws in Node. That's fine, because the
//! plugin API surface is tiny (`store`, `magic`, `directive`) and the contract is
//! well defined. This stub implements it faithfully, including the two behaviours
//! that matter:
//!
//!   * `store(name, value)` registers and `store(name)` reads back — and reads
//!     return a *reactive proxy*, so the plugin's `reactiveStore()` indirection is
//!     exercised rather than bypassed;
//!   * `effect(fn)` runs `fn` immediately and again whenever state it touched
//!     changes, which is what the visibility directives depend on.
//!
//! Real-DOM behaviour is verified separately, in an actual browser.

import type { AlpineDirective, AlpineLike } from "../src/types.ts";

type Effect = () => void;

export interface StubAlpine extends AlpineLike {
  /** Invoke a registered directive against an element. */
  runDirective: (
    name: string,
    el: HTMLElementLike,
    directive?: { value?: string; expression?: string },
  ) => void;
  /** Read a registered magic's value. */
  readMagic: (name: string) => unknown;
  readonly registeredDirectives: string[];
  readonly registeredMagics: string[];
  /** Effects registered by directives, re-run when the store changes. */
  flush: () => void;
}

/** The bits of an HTMLElement the directives touch. */
export interface HTMLElementLike {
  style: { display: string };
}

/**
 * Wraps a store so that writes re-run any effect that read from it — a minimal
 * stand-in for Alpine's reactivity.
 */
function makeReactive<T extends object>(target: T, notify: () => void): T {
  return new Proxy(target, {
    get(obj, prop, receiver) {
      const value = Reflect.get(obj, prop, receiver);
      return typeof value === "function" ? value.bind(receiver) : value;
    },
    set(obj, prop, value, receiver) {
      const ok = Reflect.set(obj, prop, value, receiver);
      notify();
      return ok;
    },
  });
}

export function createStubAlpine(): StubAlpine {
  const stores = new Map<string, unknown>();
  const magics = new Map<string, (el: Element) => unknown>();
  const directives = new Map<string, AlpineDirective>();
  const effects: Effect[] = [];

  const runEffects = (): void => {
    for (const fn of effects) fn();
  };

  const alpine: StubAlpine = {
    store(name: string, value?: unknown) {
      if (value !== undefined) {
        const reactive = makeReactive(value as object, runEffects);
        stores.set(name, reactive);
        // Alpine calls `init()` on registration, if present.
        const withInit = reactive as { init?: () => void };
        if (typeof withInit.init === "function") withInit.init();
        return reactive;
      }
      return stores.get(name);
    },
    magic(name, callback) {
      magics.set(name, callback);
    },
    directive(name, callback) {
      directives.set(name, callback);
    },
    runDirective(name, el, directive = {}) {
      const fn = directives.get(name);
      if (!fn) throw new Error(`stub: directive "${name}" is not registered`);
      fn(el as unknown as HTMLElement, directive, {
        effect: (effectFn) => {
          effects.push(effectFn);
          effectFn(); // Alpine runs an effect immediately
        },
      });
    },
    readMagic(name) {
      const fn = magics.get(name);
      if (!fn) throw new Error(`stub: magic "${name}" is not registered`);
      return fn(undefined as unknown as Element);
    },
    get registeredDirectives() {
      return [...directives.keys()];
    },
    get registeredMagics() {
      return [...magics.keys()];
    },
    flush: runEffects,
  };

  return alpine;
}

/** A minimal element double. */
export function stubElement(display = ""): HTMLElementLike {
  return { style: { display } };
}
