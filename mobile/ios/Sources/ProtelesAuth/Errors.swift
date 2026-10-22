import Foundation

/// Every failure the SDK reports — one case per outcome a caller acts on
/// differently (docs/mobile-SDKs.md §10.7).
///
/// Messages are diagnostic: log them, do not show them to end users verbatim.
public enum ProtelesAuthError: Error, Sendable, Equatable {
    /// The configuration is unusable: refused at construction (§10.1), or the
    /// server's discovery document does not fit it. Not retryable.
    case configuration(String)

    /// The user dismissed the browser. Not a failure — offer sign-in again.
    case cancelled

    /// The callback's `state` is not the one this sign-in sent. The response
    /// was not produced by this sign-in and was not read further.
    case stateMismatch

    /// An `iss` (RFC 9207 on the callback, or discovery's `issuer`) is absent
    /// or differs byte for byte from the configured issuer.
    case issuerMismatch(expected: String, received: String?)

    /// The authorization server answered the browser hop with an error, such
    /// as `access_denied`: its `error`, `error_description` and `error_uri`.
    case authorization(error: String, description: String?, errorURI: String?)

    /// The token or revocation endpoint refused a request (a 4xx), or answered
    /// `200` with a body that is not a usable response (then `error` is
    /// `invalid_response`). `error` is the OAuth error code the body carried —
    /// `nil` when it carried none, so a caller matching OAuth codes never
    /// matches one the SDK made up; `status` says what the server answered.
    case tokenEndpoint(error: String?, description: String?, status: Int)

    /// The ID token failed verification (§5, §5.2), for the reason given.
    case idTokenRejected(IDTokenRejection)

    /// The server could not be reached, or answered in a way that looks like
    /// an outage: any 5xx, from discovery, the key set, the token endpoint or
    /// the revocation endpoint (§10.9 item 4), with `status` the HTTP status
    /// it answered — `nil` when there was no answer at all. Also: another
    /// process of the app held the refresh lock for longer than the wait.
    /// Retryable.
    case network(String, status: Int? = nil)

    /// HTTP 429, from any endpoint the SDK calls. `retryAfter` is how long to
    /// wait, in seconds: the server's `Retry-After` (read as seconds or an
    /// HTTP-date, capped at an hour), or, when the server sent none the SDK
    /// can read, its own sixty-second backoff (§10.9 item 3). The client sends
    /// no token request — refresh or code exchange — and opens no browser for
    /// a sign-in before then; neither should the caller retry. The limit is
    /// per network, so other users behind the same NAT share it. The SDK
    /// always says how long; `nil` only in a value an app builds itself.
    case rateLimited(retryAfter: TimeInterval?)

    /// There is no session, or it has ended (`invalid_grant` on refresh is
    /// terminal, §4). The stored session has been cleared. Sign in again.
    case signInRequired

    /// The token store could not be read or written — for example the
    /// Keychain before the device's first unlock after a reboot. The stored
    /// session has *not* been deleted; retry later.
    case storage(String)

    /// Another sign-in or end-session is already running — on this client, or
    /// showing on this `SystemBrowser` (§10.9 item 8). This call did nothing;
    /// the running one carries on. Typically a double tap: ignore it.
    case alreadyInProgress

    /// No browser can open the sign-in or end-session page: the system would
    /// not start `ASWebAuthenticationSession`, or it failed for a reason other
    /// than the user dismissing it or the app's presentation anchor (§10.7).
    /// Nothing was sent to the server. Tell the user; retrying at once rarely
    /// helps.
    case browserUnavailable(String)
}

/// Why an ID token was refused. The raw values are the reasons
/// `mobile/vectors/reference-verify.mjs` gives, so a vector's expected
/// refusal can be compared by name.
public enum IDTokenRejection: String, Sendable, Equatable, CaseIterable {
    // From the rules in §5 and §5.2, in the order they run.
    case notThreeSegments = "not-three-segments"
    /// Not unpadded base64url, or not the one canonical spelling of its bytes.
    case headerNotBase64URL = "header-not-base64url"
    /// The header does not parse as a JSON object.
    case headerNotJSON = "header-not-json"
    /// The header or the payload names one member twice: one parser would
    /// read the first and another the last.
    case duplicateMember = "duplicate-member"
    case algorithm = "algorithm"
    /// The header carries `crit`: an extension this verifier would have to
    /// understand, and it understands none (RFC 7515 §4.1.11).
    case criticalHeader = "crit"
    case kidMissing = "kid-missing"
    /// No key in the set is an RS256 verification key with this `kid` — which
    /// includes an RSA key below 2048 bits or with an exponent below three or
    /// even.
    case noUsableKey = "no-usable-key"
    case signatureNotBase64URL = "signature-not-base64url"
    case payloadNotBase64URL = "payload-not-base64url"
    case signature = "signature"
    /// The payload does not parse as a JSON object.
    case payloadNotJSON = "payload-not-json"
    case issuer = "issuer"
    case audience = "audience"
    case subject = "sub"
    case expirationMissing = "exp-missing"
    case expired = "expired"
    case issuedInTheFuture = "issued-in-the-future"
    case nonce = "nonce"
    case atHash = "at-hash"

    // Outside a single token's bytes.
    /// The token response carried no `id_token` where one was required.
    case missing = "missing"
    /// A refresh-minted ID token names a different `sub` from the session's
    /// (OpenID Connect Core §12.2).
    case subjectChanged = "subject-changed"

    // Every reason is a verdict on the token itself. A key set that cannot be
    // fetched, or publishes no usable key, is not one: it is `.network`
    // (§10.9 item 4), as in the Android SDK. So for a refresh-minted ID token
    // every rejection is a trust failure that ends the session (§10.9 item 1);
    // the clock is not judged there (item 2), so `expired` and
    // `issuedInTheFuture` do not arise.
}

extension ProtelesAuthError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .configuration(let message):
            return "ProtelesAuth configuration error: \(message)"
        case .cancelled:
            return "The user cancelled sign-in."
        case .stateMismatch:
            return "The authorization response's state does not match this sign-in."
        case .issuerMismatch(let expected, let received):
            return "Issuer mismatch: expected \(expected), received \(received ?? "nothing")."
        case .authorization(let error, let description, _):
            return "The authorization server refused the sign-in: \(error)\(description.map { " — \($0)" } ?? "")."
        case .tokenEndpoint(let error, let description, let status):
            return "The token endpoint refused the request (HTTP \(status))\(error.map { ": \($0)" } ?? "")\(description.map { " — \($0)" } ?? "")."
        case .idTokenRejected(let reason):
            return "The ID token was rejected: \(reason.rawValue)."
        case .network(let message, _):
            // The message names the status when there was one.
            return "Network error: \(message)"
        case .rateLimited(let retryAfter):
            return "Rate limited by the authorization server\(retryAfter.map(retryPhrase) ?? "")."
        case .signInRequired:
            return "Sign-in required."
        case .storage(let message):
            return "Token storage error: \(message)"
        case .alreadyInProgress:
            return "A sign-in or end-session is already in progress."
        case .browserUnavailable(let message):
            return "No browser can show the sign-in page: \(message)"
        }
    }
}

/// "; retry after N s", rounded up. Never traps: `Int(_:)` does on a value past
/// `Int.max` or not finite, and `rateLimited` is public, so a value the SDK
/// did not produce (it caps its own at an hour) can reach here.
private func retryPhrase(_ seconds: TimeInterval) -> String {
    guard seconds.isFinite, seconds < 1_000_000_000 else { return "; retry much later" }
    return "; retry after \(Int(max(seconds, 0).rounded(.up))) s"
}

/// Anything thrown inside the SDK, as the SDK's own error type. A transport
/// failure that is not already a `ProtelesAuthError` is a network error.
func asProtelesError(_ error: any Error) -> ProtelesAuthError {
    if let error = error as? ProtelesAuthError { return error }
    return .network(String(describing: error))
}
