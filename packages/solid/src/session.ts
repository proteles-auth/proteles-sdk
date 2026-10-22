//! Fetches the current session from the BFF's `/api/auth/me`. Pure (no Svelte),
//! so it can be unit-tested with a mock fetch.

import type { AuthUser } from "./types.js";
import { meUrl } from "./urls.js";

export interface SessionResult {
  authenticated: boolean;
  user: AuthUser | null;
  /**
   * True when `/me` could not say who is signed in: it answered `503` — what
   * the BFF answers, with the session cookie left intact, while the
   * authorization server is too busy to refresh the session — or `429`, `408`
   * or another `5xx`, or nothing answered at all. `authenticated` and `user`
   * then say nothing about the session: keep what you had, and ask again.
   */
  unavailable?: boolean;
  /** With `unavailable`: the seconds the server asked for in `Retry-After`,
   *  when it named a usable wait. */
  retryAfter?: number;
}

/** GETs `/api/auth/me` with credentials.
 *
 *  A busy answer, or none, is `unavailable` rather than signed out. It used to
 *  be read as signed out like every other failure, so while the authorization
 *  server was busy the UI showed the signed-out state to users whose session
 *  was intact, until the next `/me` got through. Any other failure — a `401`, a
 *  `404` from a wrong `basePath`, a body that is not JSON — is still "not
 *  authenticated": the UI shows the signed-out state rather than throwing. */
export async function fetchSession(
  basePath: string,
  fetchImpl: typeof fetch = fetch,
): Promise<SessionResult> {
  let res: Response;
  try {
    res = await fetchImpl(meUrl(basePath), {
      credentials: "include",
      headers: { accept: "application/json" },
    });
  } catch {
    return { authenticated: false, user: null, unavailable: true };
  }
  if (isBusy(res.status)) {
    const retryAfter = parseRetryAfter(res.headers.get("retry-after"));
    return { authenticated: false, user: null, unavailable: true, ...(retryAfter === undefined ? {} : { retryAfter }) };
  }
  try {
    if (!res.ok) return { authenticated: false, user: null };
    const body = (await res.json()) as { authenticated?: boolean; user?: AuthUser };
    return { authenticated: Boolean(body.authenticated), user: body.user ?? null };
  } catch {
    return { authenticated: false, user: null };
  }
}

/** "Come back shortly", read from a status the way `OAuthError.retryable` in
 *  `@proteles/js` reads one: `408`, `429` and every `5xx`. A proxy's `502`
 *  during a deploy is as temporary as the BFF's own `503`. */
function isBusy(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

/** The longest `Retry-After` honoured, as `MAX_RETRY_AFTER_SECONDS` in
 *  `@proteles/js` caps it (`docs/mobile-SDKs.md` §10.9 item 3). */
const MAX_RETRY_AFTER_SECONDS = 3600;

/** A `Retry-After` as delta-seconds or an HTTP-date, capped at an hour;
 *  `undefined` when absent, unreadable, or already past. `parseRetryAfter` from
 *  `@proteles/js`, copied rather than imported like the rest of this file: the
 *  browser side of this package depends on no other `@proteles` package. */
function parseRetryAfter(value: string | null, now: number = Date.now()): number | undefined {
  const v = value?.trim();
  if (!v) return undefined;
  let seconds: number;
  if (/^\d+$/.test(v)) {
    seconds = Number(v);
  } else {
    const at = Date.parse(v);
    if (!Number.isFinite(at)) return undefined;
    seconds = Math.ceil((at - now) / 1000);
  }
  if (!Number.isFinite(seconds) || seconds <= 0) return undefined;
  return Math.min(seconds, MAX_RETRY_AFTER_SECONDS);
}

/** The first wait after an `unavailable` answer that named none. A full
 *  password pool at the authorization server holds on the order of a second of
 *  work. */
const FIRST_RETRY_MS = 2_000;

/** How far the wait doubles to, so a tab left open through a long outage asks
 *  about twice a minute. */
const MAX_RETRY_MS = 30_000;

export interface SessionRetry {
  /** Runs `run` once after the server's `retryAfter` when it named one, else
   *  after 2 s, then 4 s, 8 s … up to 30 s for each busy answer in a row. It
   *  replaces any retry already pending, so there is only ever one. */
  schedule: (run: () => void, retryAfter?: number) => void;
  /** Drops the pending retry, and starts the next backoff from 2 s again. */
  cancel: () => void;
}

/** When to ask `/me` again after an `unavailable` answer. One per auth state:
 *  it holds the pending timer and how many busy answers came in a row. */
export function createRetry(): SessionRetry {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let busyInARow = 0;
  return {
    schedule(run, retryAfter) {
      clearTimeout(timer);
      const backoff = Math.min(FIRST_RETRY_MS * 2 ** busyInARow, MAX_RETRY_MS);
      busyInARow += 1;
      timer = setTimeout(run, retryAfter === undefined ? backoff : retryAfter * 1000);
    },
    cancel() {
      clearTimeout(timer);
      timer = undefined;
      busyInARow = 0;
    },
  };
}

