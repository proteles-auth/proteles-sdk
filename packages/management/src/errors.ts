//! Error type for Management API calls.

/**
 * Every `error` slug `/api/v1` emits, from `spec/openapi.json`.
 *
 * Worth having as a union rather than `string`: these are the values callers
 * branch on, and the ones most worth branching on were the ones missing from
 * the prose that used to stand in for this list. `limit_reached` means a quota
 * says stop and retrying will not help; `contended` means a concurrent writer
 * won and retrying is exactly right. Opposite responses, and neither was
 * documented. `temporarily_unavailable` (503) is the second kind: the server's
 * password-hashing queue was full, nothing was written, and the same request
 * after `Retry-After` is the right next step. `rate_limited` is a third answer:
 * retrying is right, but only after a pause. The rate limiter sends it rather
 * than a handler, so every operation can return it, and a list built from the
 * handlers' error schemas alone leaves it out. `owner_unconfirmed` (403) and
 * `invitation_quota_exhausted` (429, with `Retry-After`) come from
 * `inviteUser` on a tenant self-service sign-up made: the first until an owner
 * confirms their address, the second past the daily invitation allowance until
 * a paid plan or the operator lifts it. `mail_not_configured` (409) comes from
 * `inviteTenantOwner` on a deployment with no mail relay of its own (a
 * tenant's relay does not count): nothing was sent and no invitation was
 * created, so configure the deployment's relay and send it again.
 */
export type ManagementErrorCode =
  | "invalid_request"
  | "unauthorized"
  | "forbidden"
  | "insufficient_scope"
  | "not_found"
  | "conflict"
  | "limit_reached"
  | "contended"
  | "dns_unavailable"
  | "verification_failed"
  | "rate_limited"
  | "owner_unconfirmed"
  | "invitation_quota_exhausted"
  | "mail_not_configured"
  | "server_error"
  | "temporarily_unavailable";

/**
 * A failed Management API request. `code` is the API's stable `error` slug,
 * `status` is the HTTP status, and `message` is the API's human-readable
 * message — not stable, do not match on it. `detail` is set when the server
 * could not read the request body: which field it did not know and which it
 * expected, or which value did not fit. For a person, not for matching.
 *
 * `code` is widened with `(string & {})` deliberately. A server newer than this
 * package can emit a slug the union does not name, and a client that refused to
 * carry it would be reporting a *different* error than the one that happened.
 * The union still autocompletes and still catches a typo in a literal
 * comparison; it just does not pretend to be closed.
 */
export class ManagementError extends Error {
  readonly code: ManagementErrorCode | (string & {}) | undefined;
  readonly status: number | undefined;
  readonly detail: string | undefined;

  constructor(message: string, code?: ManagementErrorCode | (string & {}), status?: number, detail?: string) {
    super(message);
    this.name = "ManagementError";
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}
