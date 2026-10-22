//! Error type surfaced by the client.

/** The longest `Retry-After` honoured, as `docs/mobile-SDKs.md` §10.9 item 3
 *  caps it: a server that asks for a day is told an hour. */
export const MAX_RETRY_AFTER_SECONDS = 3600;

/**
 * Any failure talking to the authorization server. `code` carries the OAuth
 * `error` field when the AS returned a structured error body (e.g.
 * `"invalid_grant"`); `status` carries the HTTP status when there was one.
 * Callers should treat the message as diagnostic only and never surface it
 * verbatim to end users — the Go reference deliberately shows a generic
 * message to avoid leaking configuration/account details.
 */
export class OAuthError extends Error {
  readonly code: string | undefined;
  readonly status: number | undefined;
  /**
   * How many seconds the server asked the caller to wait, from its
   * `Retry-After` — read as delta-seconds or an HTTP-date and capped at
   * {@link MAX_RETRY_AFTER_SECONDS} — when it sent a usable one. The rate
   * limiter's `429` always does, and so does the token endpoint's own `503`
   * (one second); a proxy's `503` may not.
   */
  readonly retryAfter: number | undefined;
  /**
   * True when no answer arrived at all: the request could not be sent, or the
   * timeout fired before a response did. `status` is then `undefined`.
   */
  readonly unreachable: boolean;

  constructor(
    message: string,
    code?: string,
    status?: number,
    details?: { retryAfter?: number; unreachable?: boolean },
  ) {
    super(message);
    this.name = "OAuthError";
    this.code = code;
    this.status = status;
    this.retryAfter = details?.retryAfter;
    this.unreachable = details?.unreachable ?? false;
  }

  /**
   * Whether the same request may succeed if it is made again later — "come
   * back shortly", as opposed to a verdict on what was sent.
   *
   * True when no answer arrived, and for `408`, `429` and every `5xx`. The
   * token endpoint answers `503 temporarily_unavailable` when its password
   * pool is full — a confidential client's secret went unchecked, so nothing
   * was refused — and the rate limiter answers `429`. Neither says anything
   * about the grant. A `5xx` of any other kind is treated the same way, as the
   * native SDKs treat it (`docs/mobile-SDKs.md` §10.9 item 4): a proxy's `502`
   * during a deploy is exactly as temporary.
   *
   * False for every other `4xx`, `invalid_grant` above all: the server looked
   * at the request and declined it, and will decline it again.
   */
  get retryable(): boolean {
    if (this.unreachable) return true;
    const s = this.status;
    if (s === undefined) return false;
    return s === 408 || s === 429 || s >= 500;
  }
}

/**
 * Reads a `Retry-After` header the way `docs/mobile-SDKs.md` §10.9 item 3
 * does: delta-seconds or an HTTP-date, capped at an hour. `undefined` when the
 * header is absent, unreadable, or names a moment already past — none of which
 * is a delay worth passing on.
 */
export function parseRetryAfter(value: string | null | undefined, now: number = Date.now()): number | undefined {
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
