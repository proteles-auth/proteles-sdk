//! Web Crypto access + base64url, resolved the same way as `@proteles/js`:
//! `globalThis.crypto` on browsers/edge and Node 20+, with a `node:crypto`
//! fallback for Node 18. Using Web Crypto (not `node:crypto` directly) keeps
//! the session layer usable from the Edge runtime, where Next middleware runs —
//! provided the bundler leaves the fallback's import alone; see below.

/** Thrown where `crypto.subtle` is missing and the runtime is not Node. */
const NO_SUBTLE_CRYPTO =
  "@proteles/bff: Web Crypto (crypto.subtle) is unavailable in this runtime, " +
  "and it is not Node, whose node:crypto could stand in. In a browser it needs a secure context (https, or localhost).";

async function webcrypto(): Promise<Crypto> {
  const g = globalThis as { crypto?: Crypto; process?: { versions?: { node?: string } } };
  if (typeof g.crypto?.subtle !== "undefined") {
    return g.crypto;
  }
  // As in `@proteles/js`'s crypto.ts: of the runtimes without `crypto.subtle`,
  // only Node (18) can import the fallback, so anything else gets an error that
  // says what is missing rather than a failed module resolution.
  if (!g.process?.versions?.node) {
    throw new Error(NO_SUBTLE_CRYPTO);
  }
  // Hidden from webpack for the reason given in `@proteles/js`'s crypto.ts:
  // Next.js bundles middleware for the Edge runtime, webpack resolves this
  // literal specifier whether or not it can run, and "node:crypto" does not
  // exist there. The Edge runtime has `crypto.subtle` and never gets here.
  const nodeCrypto = await import(/* webpackIgnore: true */ "node:crypto");
  return nodeCrypto.webcrypto as unknown as Crypto;
}

export async function randomBytes(length: number): Promise<Uint8Array> {
  const c = await webcrypto();
  const buf = new Uint8Array(length);
  c.getRandomValues(buf);
  return buf;
}

export async function subtle(): Promise<SubtleCrypto> {
  return (await webcrypto()).subtle;
}

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

export function base64UrlDecode(input: string): Uint8Array {
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.length % 4 === 0 ? b64 : b64 + "=".repeat(4 - (b64.length % 4));
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(padded, "base64"));
  }
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
