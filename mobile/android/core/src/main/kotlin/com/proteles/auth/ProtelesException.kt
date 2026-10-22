package com.proteles.auth

/**
 * Every failure this SDK raises: one subclass per outcome a caller acts on
 * differently (docs/mobile-SDKs.md §10.7).
 *
 * Messages are diagnostic — for logs, never for end users — and never contain a
 * token, a code or a PKCE verifier.
 */
public sealed class ProtelesException(message: String, cause: Throwable? = null) : Exception(message, cause) {

    /** The configuration cannot work: refused at construction, or found unusable at runtime (e.g. discovery is 404). */
    public class Configuration(message: String, cause: Throwable? = null) : ProtelesException(message, cause)

    /** The user dismissed the browser. Not a failure: nothing needs reporting. */
    public class Cancelled : ProtelesException("The user dismissed the browser")

    /**
     * The callback's `state` is missing or is not the one this request sent — or
     * the callback is not addressed to this request's redirect URI at all. Either
     * way it is not the response to this request.
     */
    public class StateMismatch(message: String) : ProtelesException(message)

    /**
     * An issuer did not equal the configured one byte for byte: the RFC 9207 `iss`
     * on the callback (missing counts), or the `issuer` in the discovery document.
     */
    public class IssuerMismatch(
        public val expected: String,
        /** What arrived instead; null when nothing did. */
        public val actual: String?,
        message: String,
    ) : ProtelesException(message)

    /** The authorization server returned `error` on the callback (e.g. `access_denied`). */
    public class AuthorizationError(
        public val error: String,
        public val errorDescription: String?,
        public val errorUri: String?,
    ) : ProtelesException("authorization failed: $error" + (errorDescription?.let { " ($it)" } ?: ""))

    /**
     * The token or revocation endpoint refused a request (HTTP 4xx), or answered
     * 200 with something that is not a usable response (then [error] is
     * `invalid_response`). A 5xx is [Network]: the server said "try later", not
     * "no". `invalid_grant` on a refresh is never raised as this: it is
     * [SignInRequired].
     */
    public class TokenEndpointError(
        /** The OAuth `error` code, or null when the body carried none. */
        public val error: String?,
        public val errorDescription: String?,
        public val httpStatus: Int,
    ) : ProtelesException(
        "token endpoint refused the request: " + (error ?: "HTTP $httpStatus") + (errorDescription?.let { " ($it)" } ?: ""),
    )

    /** The ID token failed verification (§5, §5.2); [reason] says which rule. */
    public class IdTokenRejected(public val reason: IdTokenRejection, detail: String) :
        ProtelesException("ID token rejected (${reason.code}): $detail")

    /**
     * The server could not be reached, or answered in a way that says "try again
     * later" — a 5xx from any endpoint, whose status is then [httpStatus]
     * (docs/mobile-SDKs.md §10.9 item 4). Also: another process of the app held
     * the cross-process lock for longer than the wait (§10.9 item 9). Retryable.
     */
    public class Network(
        message: String,
        cause: Throwable? = null,
        /**
         * The HTTP status when the server answered — a 5xx, or from discovery or the
         * key set a redirect this SDK does not follow — or null when it could not be
         * reached.
         */
        public val httpStatus: Int? = null,
    ) : ProtelesException(message, cause)

    /**
     * HTTP 429. [retryAfterSeconds] is how long this client now waits: the
     * server's `Retry-After` (seconds or an HTTP-date, capped at an hour), or
     * sixty seconds when it sent none this SDK can read (docs/mobile-SDKs.md
     * §10.9 item 3). Nothing retries automatically: until that time passes no
     * request goes to the token endpoint and no sign-in opens the browser,
     * because a request into a latched bucket keeps it latched (§2.5). Null only
     * from a [ProtelesException.RateLimited] an app builds itself.
     */
    public class RateLimited(public val retryAfterSeconds: Long?) :
        ProtelesException("rate limited" + (retryAfterSeconds?.let { "; retry after ${it}s" } ?: ""))

    /**
     * There is no usable session: nobody signed in, or the refresh token was
     * refused with `invalid_grant` (terminal — the session has been cleared).
     */
    public class SignInRequired(message: String, cause: Throwable? = null) : ProtelesException(message, cause)

    /**
     * The token store could not be read or written, or the cross-process lock
     * file could not be opened — never read as "signed out" (§10.7, added
     * 2026-09-25). The stored session has not been deleted; retry later.
     */
    public class Storage(message: String, cause: Throwable? = null) : ProtelesException(message, cause)

    /** No browser on the device can show the sign-in page (§10.7, added 2026-09-25). */
    public class BrowserUnavailable(message: String, cause: Throwable? = null) : ProtelesException(message, cause)

    /**
     * Another sign-in or end-session of this client is already showing the
     * browser (§10.7 and §10.9 item 8, added 2026-09-25). This call did nothing;
     * the running one carries on. Typically a double tap: ignore it.
     */
    public class AlreadyInProgress : ProtelesException("a sign-in or end-session is already in progress")
}

/**
 * Why an ID token was refused. [code] is the reason name
 * `mobile/vectors/reference-verify.mjs` gives the same refusal, so a vector
 * can be checked for being refused for the reason its name claims.
 */
public enum class IdTokenRejection(public val code: String) {
    NOT_THREE_SEGMENTS("not-three-segments"),
    HEADER_NOT_BASE64URL("header-not-base64url"),
    HEADER_NOT_JSON("header-not-json"),
    ALGORITHM("algorithm"),
    /** A `crit` header names an extension this verifier does not implement (RFC 7515 §4.1.11). */
    CRITICAL_HEADER("crit"),
    KID_MISSING("kid-missing"),
    NO_USABLE_KEY("no-usable-key"),
    SIGNATURE_NOT_BASE64URL("signature-not-base64url"),
    PAYLOAD_NOT_BASE64URL("payload-not-base64url"),
    SIGNATURE("signature"),
    PAYLOAD_NOT_JSON("payload-not-json"),
    /** The header or the payload names one member twice (§5.2, settled 2026-09-25). */
    DUPLICATE_MEMBER("duplicate-member"),
    ISSUER("issuer"),
    AUDIENCE("audience"),
    SUBJECT("sub"),
    EXP_MISSING("exp-missing"),
    EXPIRED("expired"),
    ISSUED_IN_THE_FUTURE("issued-in-the-future"),
    NONCE("nonce"),
    AT_HASH("at-hash"),
    /** The token response carried no `id_token` although `openid` was requested. */
    MISSING("missing"),
    /** A refresh-minted ID token names a different `sub` than the session's (OIDC Core §12.2). */
    SUBJECT_CHANGED("subject-changed"),
}
