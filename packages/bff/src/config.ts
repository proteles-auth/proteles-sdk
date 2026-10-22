//! Resolves and validates BFF configuration, merging explicit input over
//! environment variables. Fails fast with an actionable message when a
//! required value or the session key is missing/misshaped.

import { base64UrlDecode } from "./crypto.js";
import type { ProtelesConfig, ProtelesConfigInput } from "./types.js";
import { publishedAs } from "./published-secrets.js";

const DEFAULT_SCOPES = "openid profile email offline_access";
const DEFAULT_BASE_PATH = "/api/auth";
const DEFAULT_POST_LOGIN = "/";

/** Server-side diagnostics for failed logins and ignored sign-outs. Never
 *  reaches the browser. */
function defaultOnError(reason: string, context: string): void {
  // `"login"` reports a sign-in that went ahead — at the configured issuer,
  // not the one a link named — so it is not worded as a failure.
  console.warn(context === "login" ? `[proteles] ${context}: ${reason}` : `[proteles] ${context} failed: ${reason}`);
}

/** `cookieSecure` as the environment sets it: on unless
 *  `PROTELES_COOKIE_SECURE` is exactly `false`. */
export function cookieSecureFromEnv(): boolean {
  return env("PROTELES_COOKIE_SECURE") !== "false";
}

/** `endSession` as the environment sets it: on unless `PROTELES_END_SESSION`
 *  is exactly `false`, the same rule as `PROTELES_COOKIE_SECURE`. */
export function endSessionFromEnv(): boolean {
  return env("PROTELES_END_SESSION") !== "false";
}

function env(name: string): string | undefined {
  const v = globalThis.process?.env?.[name];
  return v && v.length > 0 ? v : undefined;
}

/**
 * The per-request timeout for calls to the authorization server.
 *
 * `undefined` means "leave it to `@proteles/js`", which is 10s — so the default
 * is stated in exactly one place rather than duplicated here and drifting.
 *
 * Rejects nonsense rather than absorbing it. `PROTELES_TIMEOUT_MS=abc` silently
 * becoming 10s is the kind of thing discovered during an incident, and a zero
 * or negative timeout would abort every request instantly, which looks exactly
 * like an unreachable issuer.
 */
function resolveTimeout(explicit: number | undefined): number | undefined {
  if (explicit !== undefined) {
    if (!Number.isFinite(explicit) || explicit <= 0) {
      throw new Error(`timeoutMs must be a positive number of milliseconds (got ${explicit})`);
    }
    return explicit;
  }
  const raw = env("PROTELES_TIMEOUT_MS");
  if (raw === undefined) return undefined;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`PROTELES_TIMEOUT_MS must be a positive number of milliseconds (got ${JSON.stringify(raw)})`);
  }
  return parsed;
}

function normalizeScopes(scopes: string | string[] | undefined): string | undefined {
  if (scopes === undefined) return undefined;
  return Array.isArray(scopes) ? scopes.join(" ") : scopes;
}

/** Validates that a string is base64 for exactly 32 bytes (AES-256 key). */
function assertSessionKey(secret: string): void {
  // Before the base64 and length checks, deliberately. Three of the published
  // values do not decode to 32 bytes, so a check placed after would never reach
  // them and the developer would be told "must decode to exactly 32 bytes"
  // about a key whose real problem is that everyone has it.
  const where = publishedAs(secret);
  if (where !== undefined) {
    throw new Error(
      `PROTELES_SESSION_SECRET is a value published in the Proteles repository (${where}), ` +
        `so anyone who has read it can forge a session cookie for any of your users. ` +
        `Generate a replacement with: openssl rand -base64 32`,
    );
  }
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(secret);
  } catch {
    throw new Error("PROTELES_SESSION_SECRET is not valid base64");
  }
  if (decoded.length !== 32) {
    throw new Error(`PROTELES_SESSION_SECRET must decode to exactly 32 bytes (got ${decoded.length})`);
  }
}

export function resolveConfig(input: ProtelesConfigInput = {}): ProtelesConfig {
  const issuer = input.issuer ?? env("PROTELES_ISSUER");
  const clientId = input.clientId ?? env("PROTELES_CLIENT_ID");
  const clientSecret = input.clientSecret ?? env("PROTELES_CLIENT_SECRET");
  const sessionSecret = input.sessionSecret ?? env("PROTELES_SESSION_SECRET");
  const basePath = (input.basePath ?? env("PROTELES_BASE_PATH") ?? DEFAULT_BASE_PATH).replace(/\/+$/, "");
  const appUrl = input.appUrl ?? env("PROTELES_APP_URL");
  const redirectUri =
    input.redirectUri ??
    env("PROTELES_REDIRECT_URI") ??
    (appUrl ? `${appUrl.replace(/\/+$/, "")}${basePath}/callback` : undefined);

  const missing: string[] = [];
  if (!issuer) missing.push("PROTELES_ISSUER");
  if (!clientId) missing.push("PROTELES_CLIENT_ID");
  if (!sessionSecret) missing.push("PROTELES_SESSION_SECRET");
  if (!redirectUri) missing.push("PROTELES_REDIRECT_URI (or PROTELES_APP_URL)");
  if (missing.length > 0) {
    // Named for this package, which every binding shares; it said
    // `@proteles/next` in SvelteKit, Nuxt, SolidStart and plain Node apps too.
    // The `process.env` hint is for the frameworks whose `.env` loading does not
    // reach it — Vite and SvelteKit load it into their own env modules only.
    throw new Error(
      `@proteles/bff: missing required configuration: ${missing.join(", ")} ` +
        "(pass it explicitly, or set it in process.env)",
    );
  }
  assertSessionKey(sessionSecret!);

  const cookieSecure = input.cookieSecure ?? cookieSecureFromEnv();
  const postLoginRedirect = input.postLoginRedirect ?? env("PROTELES_POST_LOGIN_REDIRECT") ?? DEFAULT_POST_LOGIN;

  return {
    issuer: issuer!,
    clientId: clientId!,
    clientSecret,
    redirectUri: redirectUri!,
    scopes: normalizeScopes(input.scopes) ?? env("PROTELES_SCOPES") ?? DEFAULT_SCOPES,
    sessionSecret: sessionSecret!,
    cookieSecure,
    postLoginRedirect,
    loginErrorRedirect: input.loginErrorRedirect ?? postLoginRedirect,
    basePath,
    endSession: input.endSession ?? endSessionFromEnv(),
    fetch: input.fetch,
    timeoutMs: resolveTimeout(input.timeoutMs),
    onError: input.onError === undefined ? defaultOnError : input.onError,
  };
}
