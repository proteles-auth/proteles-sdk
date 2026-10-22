//! ID-token verification.
//!
//! Until this existed, the SDKs treated an `id_token` as an opaque string to be
//! stored and handed back: `client.ts` copied it out of the token response,
//! `handler.ts` put it in the session, and nothing anywhere opened it. The nonce
//! was worse than unused — it was generated, sent on the authorize request, and
//! sealed into the encrypted flow cookie, and then never read. A replayed
//! `id_token` from a different login would have been accepted, because nothing
//! compared anything.
//!
//! This is a port of the verifier in Proteles' reference Go client, which is
//! the reference for the rules below; the server has another, for upstream
//! providers. This is the third implementation of the same six rules, which
//! is why all of them are held to one set of shared vectors (below).
//!
//! **The order is the security property.** A verifier that reads a claim before
//! checking the signature has already trusted the attacker's bytes.
//!
//! 1. Refuse any algorithm but `RS256`, **first**. `none` means "no signature".
//!    `HS256` means verifying an RSA token with a symmetric algorithm whose key
//!    is the *public* one — which anybody can fetch. Both are forgeries a
//!    permissive verifier accepts, and both are what "just parse the header and
//!    look up the key" produces.
//! 2. Verify the signature over the bytes **exactly as they arrived**, never a
//!    re-encoding of parsed values.
//! 3. Only then read claims: `iss`, `aud`, `exp`, `iat`.
//! 4. Compare the nonce, and treat a missing expectation as an error rather
//!    than a skip — an absent expectation silently accepting an absent nonce is
//!    the check quietly not happening.
//! 5. Check `at_hash` against the access token from the same response (M3).
//!
//! **Held to the shared vectors** (M2, `docs/mobile-SDKs.md` §5.2): the 36
//! signed tokens in `mobile/vectors/vectors.json`, which the native SDKs
//! and `reference-verify.mjs` are held to as well, run by
//! `test/vectors.test.ts`. So the issuer is compared byte for byte, one
//! audience is accepted and it must be this client, base64url has exactly one
//! spelling, `crit` and a member named twice are refused, and a key below 2048
//! bits or with an exponent of one is not a key. Before this ran, ten of the 36
//! reached the wrong verdict here.
//!
//! No dependency. WebCrypto's `RSASSA-PKCS1-v1_5`/`SHA-256` is exactly RS256,
//! and it is present in every runtime this SDK targets. A JOSE library here
//! would be a third-party dependency inside an authentication path, bought for
//! roughly eighty lines.

import { DEFAULT_TIMEOUT_MS } from "./client.js";
import { subtle } from "./crypto.js";
import { OAuthError, parseRetryAfter } from "./errors.js";
import type { FetchLike } from "./types.js";

/** Tolerance for clock differences between this host and the issuer. */
const CLOCK_SKEW_SECONDS = 60;

/** How long a fetched key set is reused before refetching. */
const JWKS_TTL_MS = 10 * 60 * 1000;

/**
 * How long after one refetch for an unknown `kid` the next may happen. The
 * kid is read before the signature is checked, and `verifyLogoutToken` runs on
 * an unauthenticated POST, so without a floor every token naming a made-up kid
 * was one request to the issuer. Measured from the last refetch an unknown kid
 * caused, not from the last fetch: a rotation is the only thing that causes
 * one in ordinary running, so it is never held back unless somebody has been
 * sending made-up kids in the half minute before it.
 *
 * **One window per kind of token.** With one
 * window for the cache, made-up kids POSTed to the back-channel logout route
 * every thirty seconds kept it armed, and an ID token from the token endpoint
 * naming a freshly rotated key was refused until the set's TTL ran out — up to
 * ten minutes of failed sign-ins and refreshes for an app sharing one cache,
 * which the README's "one per process" invites. Logout tokens and ID tokens
 * now hold back only their own kind; the issuer still sees at most one
 * refetch per window per kind.
 */
const UNKNOWN_KID_REFETCH_MS = 30_000;

/** The claims this SDK reads. Others are carried through untouched. */
export interface IdTokenClaims {
  iss: string;
  /** Always normalised to an array: the spec allows either form. */
  aud: string[];
  sub: string;
  exp: number;
  iat?: number;
  nonce?: string;
  auth_time?: number;
  amr?: string[];
  email?: string;
  email_verified?: boolean;
  preferred_username?: string;
  /**
   * What this client calls the session (OIDC Back-Channel Logout 1.0 §2.1):
   * keep it with the session, so a logout token naming it can end that one.
   */
  sid?: string;
  [claim: string]: unknown;
}

export interface VerifyIdTokenOptions {
  /**
   * The issuer this token must name, byte for byte (`docs/mobile-SDKs.md` §5.2
   * #2). The server emits one spelling per tenant, `scheme://host` with no
   * trailing slash, and normalising a slash is how two issuers become one.
   */
  issuer: string;
  /** The client id that must appear in `aud`. */
  audience: string;
  /**
   * The nonce this login sent, or `null` for a token that cannot carry one.
   *
   * `null` is deliberately explicit rather than "omit it". The refresh grant
   * mints an `id_token` with no nonce — there is no authorize request to have
   * carried one — so refresh paths must pass `null` and say so. An optional
   * parameter would let a *callback* forget it and get the same silent pass,
   * which is the check not happening.
   */
  nonce: string | null;
  /**
   * The access token that came in the same response, or `null` when there is
   * none. When it is given, the token's `at_hash` must be present and match it
   * (M3): that is what binds the two halves of one response together.
   *
   * Explicit for the reason `nonce` is: an optional parameter would let a
   * caller that holds the access token forget it and skip the check.
   */
  accessToken: string | null;
  jwks: JwksCache;
  now?: () => number;
}

/** Bytes to base64url, unpadded. */
function bytesToB64u(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Base64url to bytes, strictly: the unpadded alphabet only (§5.2 #6), and
 * only the one spelling of those bytes.
 *
 * `atob` is forgiving. It accepts padding, and it ignores a final character's
 * unused bits, so two spellings decode to the same bytes here and to
 * different ones in a stricter decoder. Two verifiers would then disagree
 * about what was signed. Re-encoding and comparing refuses every spelling but
 * the canonical one.
 */
function b64uToBytes(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new Error("not base64url");
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  if (bytesToB64u(out) !== s) throw new Error("not the canonical spelling");
  return out;
}

function b64uToString(s: string): string {
  return new TextDecoder().decode(b64uToBytes(s));
}

/**
 * Whether a JOSE `typ` names a logout token: `logout+jwt`, in any case, with
 * or without the `application/` prefix that RFC 7515 §4.1.9 says a recipient
 * must treat as implied.
 */
function isLogoutTokenType(typ: unknown): boolean {
  if (typeof typ !== "string") return false;
  const t = typ.toLowerCase();
  return t === "logout+jwt" || t === "application/logout+jwt";
}

/** `aud` as a list, a claim of the wrong type reading as absent. */
function audiences(aud: unknown): string[] {
  return Array.isArray(aud) ? aud.map((a) => (typeof a === "string" ? a : "")) : typeof aud === "string" ? [aud] : [];
}

/** Length-independent comparison, for the nonce. */
function constantTimeEqual(a: string, b: string): boolean {
  const ab = new TextEncoder().encode(a);
  const bb = new TextEncoder().encode(b);
  // Compare a fixed number of bytes either way so the loop count does not
  // depend on where the first difference is.
  let diff = ab.length ^ bb.length;
  const n = Math.max(ab.length, bb.length);
  for (let i = 0; i < n; i += 1) diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  return diff === 0;
}

/**
 * JSON, refusing an object that names one member twice (§5.2).
 *
 * `JSON.parse` keeps the last of two members with one name; a parser that keeps
 * the first reads a different token from the same bytes. So the text is parsed
 * once for its value, and scanned once for repeated names in any object.
 * "Twice" means the same code units (RFC 8259 §8.3): `é` and `e` followed by a
 * combining accent are two names.
 */
function parseStrict(text: string): unknown {
  const value: unknown = JSON.parse(text);
  let i = 0;
  const ws = () => {
    while (i < text.length && " \t\n\r".includes(text[i] ?? "")) i += 1;
  };
  const str = (): string => {
    const start = i;
    i += 1;
    while (text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
    i += 1;
    return JSON.parse(text.slice(start, i)) as string;
  };
  const val = (): void => {
    ws();
    const c = text[i];
    if (c === "{") {
      i += 1;
      const seen = new Set<string>();
      ws();
      if (text[i] === "}") {
        i += 1;
        return;
      }
      for (;;) {
        ws();
        const key = str();
        if (seen.has(key)) throw new Error(`the member ${JSON.stringify(key)} is named twice`);
        seen.add(key);
        ws();
        i += 1; // the colon
        val();
        ws();
        if (text[i++] === "}") return;
      }
    } else if (c === "[") {
      i += 1;
      ws();
      if (text[i] === "]") {
        i += 1;
        return;
      }
      for (;;) {
        val();
        ws();
        if (text[i++] === "]") return;
      }
    } else if (c === '"') {
      str();
    } else {
      while (i < text.length && !",]} \t\n\r".includes(text[i] ?? "")) i += 1;
    }
  };
  val();
  return value;
}

/**
 * Whether an RSA key is one this verifier will trust: a modulus of at least
 * 2048 bits, the server's own floor, and an odd exponent of at least three.
 * With an exponent of one the "signature" is the padded digest itself, which
 * anybody can write.
 */
function rsaKeyIsSound(n: string, e: string): boolean {
  let modulus: Uint8Array;
  let exponent: Uint8Array;
  try {
    modulus = b64uToBytes(n);
    exponent = b64uToBytes(e);
  } catch {
    return false;
  }
  let first = 0;
  while (first < modulus.length && modulus[first] === 0) first += 1;
  const lead = modulus[first] ?? 0;
  const bits = first === modulus.length ? 0 : (modulus.length - first - 1) * 8 + (32 - Math.clz32(lead));
  let exp = 0n;
  for (const b of exponent) exp = (exp << 8n) | BigInt(b);
  return bits >= 2048 && exp >= 3n && exp % 2n === 1n;
}

interface JwkEntry {
  kty?: string;
  alg?: string;
  kid?: string;
  n?: string;
  e?: string;
  use?: string;
}

/**
 * The published signing keys, cached, with the one behaviour that matters:
 * **an unknown `kid` triggers a refetch**, because that is what a rotation looks
 * like from here. Without it every login fails from the moment the server rotates
 * until the TTL happens to lapse.
 *
 * A stale-but-present key is preferred to failing when the refetch itself fails,
 * so a brief JWKS outage does not sign everybody out. An unknown kid has nothing
 * to fall back to and is an error.
 *
 * A fetch that fails says how, in the `OAuthError` it throws: `unreachable`
 * when no answer came, `status` (and `retryAfter`) when a non-`2xx` did — so
 * `retryable` tells "the key set could not be read just now" from "the key set
 * says no". `docs/mobile-SDKs.md` §10.9 item 4 has the native SDKs treat a key-set
 * `5xx` as the network error, not as a verdict on the token, and a caller
 * holding a freshly rotated refresh token needs the same distinction to know
 * whether to keep it.
 *
 * A fetch that has not finished within `timeoutMs` (the client's default, ten
 * seconds, unless the caller passes its own) is abandoned and fails as
 * unreachable. Every callback and every refresh that carries an ID token waits
 * on it, so an endpoint that accepted the connection and never answered held
 * all of them open with it. And an unknown kid refetches at most once every
 * {@link UNKNOWN_KID_REFETCH_MS}; one that arrives sooner is refused against
 * the set already held.
 */
export class JwksCache {
  #uri: string;
  #fetch: FetchLike;
  #timeoutMs: number;
  #keys = new Map<string, CryptoKey>();
  #fetchedAt = 0;
  /** When an unknown kid last caused a refetch, per `what` (one window per kind of token). */
  #unknownKidRefetchAt = new Map<string, number>();
  #inFlight: Promise<void> | null = null;

  constructor(jwksUri: string, fetchImpl?: FetchLike, options?: { timeoutMs?: number }) {
    this.#uri = jwksUri;
    this.#fetch = fetchImpl ?? (globalThis.fetch as FetchLike);
    this.#timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  async keyFor(kid: string | undefined, now: number, what = "id_token"): Promise<CryptoKey> {
    if (!kid) throw new OAuthError(`${what} header has no kid`, "invalid_token");

    const cached = this.#keys.get(kid);
    const current = now - this.#fetchedAt < JWKS_TTL_MS;
    if (cached && current) return cached;

    // A current set that lacks this kid is fetched again only if no other
    // unknown kid has caused that lately. An empty or expired set is always
    // fetched: that is the ordinary refill, not a guess at a rotation.
    if (!cached && current && this.#keys.size > 0) {
      if (now - (this.#unknownKidRefetchAt.get(what) ?? Number.NEGATIVE_INFINITY) < UNKNOWN_KID_REFETCH_MS) {
        throw new OAuthError(
          `no signing key is published for kid "${kid}" in the key set fetched ${Math.round((now - this.#fetchedAt) / 1000)} s ago`,
          "invalid_token",
        );
      }
      this.#unknownKidRefetchAt.set(what, now);
    }

    try {
      await this.#refresh();
    } catch (err) {
      // Stale beats signing everybody out while the issuer is briefly
      // unreachable — but only if we actually hold this key.
      if (cached) return cached;
      throw err;
    }

    const fresh = this.#keys.get(kid);
    if (!fresh) {
      throw new OAuthError(`no signing key is published for kid "${kid}"`, "invalid_token");
    }
    return fresh;
  }

  /** Collapses concurrent refreshes, so a burst of logins is one fetch. */
  async #refresh(): Promise<void> {
    if (this.#inFlight) return this.#inFlight;
    this.#inFlight = (async () => {
      // Over the body as well as the headers: an answer that stops halfway
      // holds the caller just as long as one that never starts.
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
      const unreachable = (err: unknown) =>
        new OAuthError(
          controller.signal.aborted
            ? `jwks endpoint did not answer within ${this.#timeoutMs} ms`
            : `jwks endpoint could not be reached: ${(err as Error).message}`,
          "invalid_token",
          undefined,
          { unreachable: true },
        );
      try {
        let res: Response;
        try {
          res = await this.#fetch(this.#uri, { headers: { accept: "application/json" }, signal: controller.signal });
        } catch (err) {
          throw unreachable(err);
        }
        if (!res.ok) {
          throw new OAuthError(`jwks endpoint returned HTTP ${res.status}`, "invalid_token", res.status, {
            retryAfter: parseRetryAfter(res.headers.get("retry-after")),
          });
        }
        let doc: { keys?: JwkEntry[] };
        try {
          doc = (await res.json()) as { keys?: JwkEntry[] };
        } catch (err) {
          if (controller.signal.aborted) throw unreachable(err);
          throw err;
        }
        const s = await subtle();
        const next = new Map<string, CryptoKey>();
        for (const jwk of doc.keys ?? []) {
          // Only RS256 signing keys. An encryption key or an EC key in the
          // document is not an error — it is simply not a key this verifier
          // would ever select, and importing it would fail later and less
          // clearly.
          if (jwk.kty !== "RSA" || !jwk.kid || !jwk.n || !jwk.e) continue;
          if (jwk.alg && jwk.alg !== "RS256") continue;
          if (jwk.use && jwk.use !== "sig") continue;
          if (!rsaKeyIsSound(jwk.n, jwk.e)) continue;
          const key = await s.importKey(
            "jwk",
            { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            false,
            ["verify"],
          );
          next.set(jwk.kid, key);
        }
        if (next.size === 0) {
          // A document with no usable key is a misconfiguration, and accepting
          // it would leave the cache empty and every login failing with
          // "unknown kid" — which points at the wrong thing.
          throw new OAuthError("jwks document published no usable RS256 signing key", "invalid_token");
        }
        this.#keys = next;
        this.#fetchedAt = Date.now();
      } finally {
        clearTimeout(timer);
        this.#inFlight = null;
      }
    })();
    return this.#inFlight;
  }
}

/**
 * Rules 1 and 2, for any JWS this issuer signs: the algorithm checked first,
 * the signature verified over the bytes as they arrived, and only then the
 * payload parsed — strictly, as an object. Shared by the ID token and the
 * logout token so the two cannot drift apart on the part that decides whether
 * any claim is worth reading. `what` names the token in the error messages.
 */
async function verifiedJws(
  raw: string,
  jwks: JwksCache,
  nowMs: number,
  what: string,
): Promise<{ header: { alg?: string; kid?: string; typ?: unknown }; payload: Record<string, unknown> }> {
  const parts = raw.split(".");
  if (parts.length !== 3) {
    throw new OAuthError(`${what} is not a three-part JWS`, "invalid_token");
  }
  // Destructured with an explicit guard rather than `!`: `noUncheckedIndexedAccess`
  // is on, and the three-part check above is what makes these present.
  const headerB64 = parts[0] ?? "";
  const payloadB64 = parts[1] ?? "";
  const sigB64 = parts[2] ?? "";

  let header: { alg?: string; kid?: string; crit?: unknown; typ?: unknown };
  try {
    header = parseStrict(b64uToString(headerB64)) as typeof header;
  } catch {
    throw new OAuthError(`${what} header is not valid base64url JSON`, "invalid_token");
  }
  if (header === null || typeof header !== "object" || Array.isArray(header)) {
    throw new OAuthError(`${what} header is not a JSON object`, "invalid_token");
  }

  // Rule 1, before the key lookup and before any claim is read.
  if (header.alg !== "RS256") {
    throw new OAuthError(`${what} alg is ${JSON.stringify(header.alg ?? null)}; only RS256 is accepted`,
      "invalid_token",
    );
  }
  // A header extension the sender marked critical must be understood to accept
  // the token (RFC 7515 §4.1.11), and this verifier understands none.
  if ("crit" in header) {
    throw new OAuthError(`${what} header names a critical extension this verifier does not understand`, "invalid_token");
  }

  const key = await jwks.keyFor(header.kid, nowMs, what);

  // Rule 2: over the bytes as they arrived.
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  let signature: Uint8Array;
  try {
    signature = b64uToBytes(sigB64);
  } catch {
    throw new OAuthError(`${what} signature is not valid base64url`, "invalid_token");
  }
  const ok = await (await subtle()).verify(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    signature as unknown as BufferSource,
    signingInput as unknown as BufferSource,
  );
  if (!ok) throw new OAuthError(`${what} signature does not verify`, "invalid_token");

  let payload: Record<string, unknown>;
  try {
    const parsed = parseStrict(b64uToString(payloadB64)) as Record<string, unknown>;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    payload = parsed;
  } catch {
    throw new OAuthError(`${what} payload is not valid base64url JSON`, "invalid_token");
  }
  return { header, payload };
}

/**
 * Verifies an ID token and returns its claims, or throws `OAuthError`.
 *
 * Exported as its own function rather than folded into `exchangeCode` so the
 * published API stays additive — and so the refresh paths, which have no nonce
 * to compare, can call it without a second code path inside the exchange.
 */
export async function verifyIdToken(
  raw: string,
  opts: VerifyIdTokenOptions,
): Promise<IdTokenClaims> {
  const nowMs = (opts.now ?? Date.now)();
  const { header, payload: parsed } = await verifiedJws(raw, opts.jwks, nowMs, "id_token");
  // A logout token carries `iss`, one `aud`, `sub` and `exp` too, so a caller
  // with no nonce and no access token to compare would otherwise take one for
  // an ID token. Its type says what it is (Back-Channel Logout 1.0 §2.4).
  if (isLogoutTokenType(header.typ)) {
    throw new OAuthError("id_token is typed as a logout token", "invalid_token");
  }

  // Rule 3: only now are the claims worth reading.
  const aud = parsed["aud"];
  // Taken as the types they must be, never coerced: `String(["https://a"])`
  // is `"https://a"`, so coercing would let an array stand in for an issuer.
  // A claim of the wrong type is read as absent, and the checks below refuse
  // it as missing.
  const claims = {
    ...parsed,
    iss: typeof parsed["iss"] === "string" ? parsed["iss"] : "",
    sub: typeof parsed["sub"] === "string" ? parsed["sub"] : "",
    aud: audiences(aud),
    exp: typeof parsed["exp"] === "number" ? parsed["exp"] : 0,
  } as IdTokenClaims;

  if (claims.iss !== opts.issuer) {
    throw new OAuthError(`id_token issuer ${JSON.stringify(claims.iss)} is not ${JSON.stringify(opts.issuer)}`,
      "invalid_token",
    );
  }
  // One audience, and it is this client. Several would need `azp`, which this
  // issuer never sends, so a token naming another client too is refused.
  if (claims.aud.length !== 1 || claims.aud[0] !== opts.audience) {
    throw new OAuthError(`id_token audience ${JSON.stringify(claims.aud)} is not ${JSON.stringify([opts.audience])}`,
      "invalid_token",
    );
  }
  if (!claims.sub) throw new OAuthError("id_token has no sub", "invalid_token");

  const nowSec = Math.floor(nowMs / 1000);
  if (!claims.exp) throw new OAuthError("id_token has no exp", "invalid_token");
  if (nowSec > claims.exp + CLOCK_SKEW_SECONDS) {
    throw new OAuthError("id_token has expired", "invalid_token");
  }
  if (typeof claims.iat === "number" && nowSec + CLOCK_SKEW_SECONDS < claims.iat) {
    throw new OAuthError("id_token was issued in the future", "invalid_token");
  }

  // Rule 4. `null` means "this grant cannot carry one" and is the only way to
  // skip the comparison; an *expected* nonce that is empty is a login whose
  // nonce was lost, which must not pass.
  if (opts.nonce !== null) {
    if (!opts.nonce) {
      throw new OAuthError("no nonce was recorded for this login", "invalid_token");
    }
    if (!claims.nonce || !constantTimeEqual(claims.nonce, opts.nonce)) {
      throw new OAuthError("id_token nonce does not match the one this login sent", "invalid_token");
    }
  }

  // Rule 5 (M3): the access token from the same response, bound by `at_hash`.
  // The left half of its SHA-256, base64url: RS256's hash, as OIDC Core §3.1.3.6
  // defines it. Omitted is not `null`: a JavaScript caller that leaves it out
  // is told so, rather than refused for a hash of nothing.
  if (opts.accessToken === undefined) {
    throw new OAuthError("accessToken is required: the access token from the same response, or null", "invalid_token");
  }
  if (opts.accessToken !== null) {
    const digest = new Uint8Array(
      await (await subtle()).digest("SHA-256", new TextEncoder().encode(opts.accessToken) as unknown as BufferSource),
    );
    const expected = bytesToB64u(digest.subarray(0, digest.length / 2));
    if (claims["at_hash"] !== expected) {
      throw new OAuthError("id_token at_hash does not match the access token it came with", "invalid_token");
    }
  }

  return claims;
}

/** The `events` member that makes a JWT a logout token (Back-Channel Logout 1.0 §2.4). */
export const BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

/** The claims of a verified logout token. */
export interface LogoutTokenClaims {
  iss: string;
  /** Always normalised to an array, as an ID token's is. */
  aud: string[];
  iat: number;
  exp: number;
  /**
   * The token's id. A retry from this server repeats it — signed again, with a
   * fresh `exp`, possibly hours later — so a relying party that remembers it
   * can tell a retry from a new logout. §2.6 makes refusing a seen one
   * optional, and ending a session that already ended is harmless (§2.7), so
   * acting twice is safe; refusing one that was recorded but never acted on
   * would lose the logout.
   */
  jti: string;
  /** The person whose session ended. Proteles always sends it. */
  sub?: string;
  /**
   * Which of their sessions, as the `sid` in the ID tokens this client was
   * issued. End that session; with no `sid`, end every session of `sub`.
   */
  sid?: string;
  events: Record<string, unknown>;
  [claim: string]: unknown;
}

export interface VerifyLogoutTokenOptions {
  /** The issuer this client's ID tokens carry, byte for byte. */
  issuer: string;
  /** This client's id, which must be the token's one audience. */
  audience: string;
  jwks: JwksCache;
  now?: () => number;
}

/**
 * Verifies a logout token (OIDC Back-Channel Logout 1.0 §2.6) and returns its
 * claims, or throws `OAuthError`. What a relying party's
 * `backchannel_logout_uri` calls on the `logout_token` form field before it
 * ends anything. Answer `200` once the session has ended. When this throws,
 * answer `400` (§2.8) — **unless `err.retryable`**: the key set could not be
 * read just now, which says nothing about the token, so answer `503` and the
 * server tries again later. A `400` is final; it is never retried.
 *
 * The signature is checked by the code that checks ID tokens (`verifiedJws`):
 * the algorithm first, then the signature over the bytes as they arrived, then
 * a strict parse. The issuer and audience are compared as an ID token's are.
 * Then §2.6's own rules: `iat` and `exp` present and in range; the
 * back-channel logout member in `events`, as an object; a `sub` or a `sid`; a
 * `jti`; and no `nonce`, which an ID token from a login has and a logout token
 * never does. The header must type it `logout+jwt` (`application/logout+jwt`
 * is the same type), as this server always does; §4.1 notes that requiring it
 * refuses untyped tokens from other servers, which this SDK is not for.
 *
 * It does not remember `jti`s: whether to, and where, is the caller's (§2.6
 * makes it optional), and a process-local set would be wrong behind a load
 * balancer.
 */
export async function verifyLogoutToken(raw: string, opts: VerifyLogoutTokenOptions): Promise<LogoutTokenClaims> {
  const nowMs = (opts.now ?? Date.now)();
  const { header, payload } = await verifiedJws(raw, opts.jwks, nowMs, "logout token");

  if (!isLogoutTokenType(header.typ)) {
    throw new OAuthError(`logout token typ is ${JSON.stringify(header.typ ?? null)}, not "logout+jwt"`, "invalid_token");
  }
  const str = (k: string) => (typeof payload[k] === "string" ? (payload[k] as string) : undefined);
  const num = (k: string) => (typeof payload[k] === "number" ? (payload[k] as number) : undefined);

  const iss = str("iss") ?? "";
  if (iss !== opts.issuer) {
    throw new OAuthError(`logout token issuer ${JSON.stringify(iss)} is not ${JSON.stringify(opts.issuer)}`, "invalid_token");
  }
  const aud = audiences(payload["aud"]);
  if (aud.length !== 1 || aud[0] !== opts.audience) {
    throw new OAuthError(`logout token audience ${JSON.stringify(aud)} is not ${JSON.stringify([opts.audience])}`,
      "invalid_token",
    );
  }

  const nowSec = Math.floor(nowMs / 1000);
  const iat = num("iat");
  const exp = num("exp");
  if (iat === undefined) throw new OAuthError("logout token has no iat", "invalid_token");
  if (exp === undefined) throw new OAuthError("logout token has no exp", "invalid_token");
  if (nowSec + CLOCK_SKEW_SECONDS < iat) throw new OAuthError("logout token was issued in the future", "invalid_token");
  if (nowSec > exp + CLOCK_SKEW_SECONDS) throw new OAuthError("logout token has expired", "invalid_token");

  const events = payload["events"];
  if (
    events === null ||
    typeof events !== "object" ||
    Array.isArray(events) ||
    // An absent member reads as `undefined`, so this also refuses one that
    // is not there.
    typeof (events as Record<string, unknown>)[BACKCHANNEL_LOGOUT_EVENT] !== "object" ||
    (events as Record<string, unknown>)[BACKCHANNEL_LOGOUT_EVENT] === null ||
    Array.isArray((events as Record<string, unknown>)[BACKCHANNEL_LOGOUT_EVENT])
  ) {
    throw new OAuthError("logout token events do not name a back-channel logout", "invalid_token");
  }
  const sub = str("sub");
  const sid = str("sid");
  if (!sub && !sid) throw new OAuthError("logout token names neither a sub nor a sid", "invalid_token");
  const jti = str("jti");
  if (!jti) throw new OAuthError("logout token has no jti", "invalid_token");
  if ("nonce" in payload) throw new OAuthError("logout token carries a nonce, so it is not a logout token", "invalid_token");

  // A `sub` or `sid` of the wrong type reads as absent, as an ID token's
  // claims do, rather than passing through under a type that says string.
  const { sub: _sub, sid: _sid, ...rest } = payload;
  return {
    ...rest,
    iss,
    aud,
    iat,
    exp,
    jti,
    ...(sub ? { sub } : {}),
    ...(sid ? { sid } : {}),
    events: events as Record<string, unknown>,
  };
}
