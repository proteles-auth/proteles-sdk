// A register of secrets Proteles has published, kept in step with the
// Proteles server's own register.
//
// The server refuses these by name at boot. A BFF built on this package did
// not, so the same value the server rejects would encrypt every session
// cookie the app issues. The duplication is forced by the language boundary,
// and a silent divergence is the only thing about it that would actually
// hurt, so the two are compared whenever either changes. Each `publishedAs`
// names where the value appeared in the Proteles server's source, which is
// what a refusal tells the developer.
//
// A register, not a judgement. It lists values *actually committed to a
// Proteles repository*, and is deliberately not extended to values that merely look
// weak. Entries are never removed: a key published once is published for good.
export interface PublishedSecret {
  readonly value: string;
  readonly publishedAs: string;
}

export const PUBLISHED_SECRETS: readonly PublishedSecret[] = [
  {
    value: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
    publishedAs:
      "the KEK docker-compose.yml shipped before it was replaced, and long the default session key in the SDK verify scripts",
  },
  {
    value: "ePCDmiNNr9KI2tk5dFieM42LFIv4LS0nfZVfalGXZqY=",
    publishedAs:
      "the KEK docker-compose.yml shipped after that, and the key scripts/e2e-smoke-test.sh hardcoded as KEK_V1_B64",
  },
  {
    value: "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=",
    publishedAs: "the rotation target scripts/e2e-smoke-test.sh hardcoded as KEK_V2_B64",
  },
  {
    value: "bSODj8hZSrqKFx/kkql7nMSYEYpTydSneWhB1cW6L/E=",
    publishedAs: "the dashboard SESSION_KEY_B64 docker-compose.yml shipped",
  },
  {
    value: "local-development-only-not-a-secret-32b+",
    publishedAs: "the SESSION_SECRET docker-compose.yml shipped",
  },
  {
    value: "e2e-smoke-test-session-secret-not-for-prod",
    publishedAs: "the SESSION_SECRET scripts/e2e-smoke-test.sh hardcoded",
  },
  {
    value: "e2e-rotated-session-secret-also-not-for-production",
    publishedAs: "the rotation target scripts/e2e-smoke-test.sh hardcoded",
  },
  {
    value: "CHANGE_ME_32_RANDOM_BYTES_BASE64",
    publishedAs: "the placeholder in oauth-server/.env.example",
  },
  {
    value: "CHANGE_ME_TO_AT_LEAST_32_RANDOM_BYTES_SEE_ABOVE",
    publishedAs:
      "the placeholder oauth-server/.env.example used to carry, which was long enough to clear the 32-byte floor and boot",
  },
  {
    value: "e2e-platform-bootstrap-token",
    publishedAs: "the MANAGEMENT_BOOTSTRAP_TOKEN scripts/e2e-smoke-test.sh hardcoded",
  },
  {
    value: "e2e-metrics-scrape-token",
    publishedAs: "the METRICS_TOKEN scripts/e2e-smoke-test.sh hardcoded",
  },
  {
    value: "your-platform-token",
    publishedAs: "the MANAGEMENT_BOOTSTRAP_TOKEN dashboard/README.md showed",
  },
];

/**
 * Where a candidate was published, or `undefined` if it was not.
 *
 * Trims first: `openssl rand -base64 32 > file` and `echo` both leave a
 * newline, and a check a newline defeats is a check the usual case defeats.
 *
 * Compares the trimmed *string*, never decoded bytes. `base64UrlDecode` maps
 * `-`/`_` onto `+`/`/` and repads, so a decoded comparison would quietly widen
 * this from "was published" to "is equivalent to something published" — the
 * first step toward the entropy oracle this register exists not to be. Six
 * entries are not valid base64 at all.
 */
export function publishedAs(candidate: string): string | undefined {
  const trimmed = candidate.trim();
  return PUBLISHED_SECRETS.find((p) => p.value === trimmed)?.publishedAs;
}
