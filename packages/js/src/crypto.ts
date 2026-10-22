//! Runtime-agnostic access to Web Crypto + base64url, the two primitives PKCE
//! needs. Browsers and edge runtimes expose `globalThis.crypto`; Node 20+ does
//! too, but Node 18 does not — there we fall back to the `node:crypto`
//! `webcrypto` export. The dynamic import is only *evaluated* on that fallback
//! path, but a bundler still sees it: see the comment on the import.

/** Thrown where `crypto.subtle` is missing and the runtime is not Node. */
const NO_SUBTLE_CRYPTO =
  "@proteles/js: Web Crypto (crypto.subtle) is unavailable. Browsers provide it only in a " +
  "secure context: serve the page over https, or from localhost.";

async function webcrypto(): Promise<Crypto> {
  const g = globalThis as { crypto?: Crypto; process?: { versions?: { node?: string } } };
  if (typeof g.crypto?.subtle !== "undefined") {
    return g.crypto;
  }
  // Two runtimes get here. Node 18, which has `node:crypto` to fall back to;
  // and a browser on a page that is not a secure context (plain http on any
  // host but localhost), which has `globalThis.crypto` but withholds `subtle`.
  // The import below cannot work in a browser, and fails there with "Failed to
  // resolve module specifier", which names neither cause nor cure.
  if (!g.process?.versions?.node) {
    throw new Error(NO_SUBTLE_CRYPTO);
  }
  // `webpackIgnore` leaves this import to the runtime. webpack resolves every
  // literal `import()` it can see, reachable or not, and Next.js bundles
  // middleware for the Edge runtime, which has no `node:` modules — so without
  // it `next build` failed with UnhandledSchemeError on "node:crypto", and
  // every request to a Next app using `@proteles/next` middleware was a 500
  // (found running the quickstart, 2026-09-29). The Edge runtime has
  // `crypto.subtle`, so it never reaches this line; only Node does.
  const nodeCrypto = await import(/* webpackIgnore: true */ "node:crypto");
  return nodeCrypto.webcrypto as unknown as Crypto;
}

/** `crypto.subtle`, from wherever this runtime keeps it. The ID-token
 *  verifier needs it too, and on Node 18 the bare global is not there. */
export async function subtle(): Promise<SubtleCrypto> {
  return (await webcrypto()).subtle;
}

/** Cryptographically-strong random bytes. */
export async function randomBytes(length: number): Promise<Uint8Array> {
  const c = await webcrypto();
  const buf = new Uint8Array(length);
  c.getRandomValues(buf);
  return buf;
}

/** SHA-256 digest of `data`. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const c = await webcrypto();
  // Copy into a standalone ArrayBuffer: `subtle.digest` wants a `BufferSource`,
  // and this sidesteps TS 5.7's `Uint8Array<ArrayBufferLike>` vs. `ArrayBuffer`
  // view-generic incompatibility without an unsafe cast.
  const buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  const digest = await c.subtle.digest("SHA-256", buffer);
  return new Uint8Array(digest);
}

/** Base64url-encode without padding (RFC 4648 §5), matching the server. */
export function base64UrlEncode(bytes: Uint8Array): string {
  let base64: string;
  if (typeof Buffer !== "undefined") {
    base64 = Buffer.from(bytes).toString("base64");
  } else {
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    base64 = btoa(binary);
  }
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Base64-encode a UTF-8 string (used for HTTP Basic client authentication). */
export function base64(input: string): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(input, "utf8").toString("base64");
  }
  return btoa(unescape(encodeURIComponent(input)));
}
