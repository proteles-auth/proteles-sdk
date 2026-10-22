import Foundation

/// The signed-in user: the claims of the last verified ID token.
///
/// Cached as claims, not as a token — the ID token expires with the access
/// token, fifteen minutes by default, and the user does not (trap 7).
public struct UserClaims: Sendable, Equatable {
    /// Every claim, as verified.
    public let raw: [String: JSONValue]

    init(_ claims: [String: JSONValue]) {
        raw = claims
    }

    /// `sub` — the stable identifier for this user at this tenant.
    public var subject: String { raw["sub"]?.stringValue ?? "" }
    /// `iss` — the tenant's issuer.
    public var issuer: String { raw["iss"]?.stringValue ?? "" }
    public var email: String? { raw["email"]?.stringValue }
    public var emailVerified: Bool? { raw["email_verified"]?.boolValue }
    public var preferredUsername: String? { raw["preferred_username"]?.stringValue }
    /// When the user last authenticated. Inherited across refreshes, never
    /// restamped (trap 8), so `max_age` and step-up keep their meaning.
    public var authTime: Date? { raw["auth_time"]?.numberValue.map { Date(timeIntervalSince1970: $0) } }
    /// Authentication methods, e.g. `["pwd", "mfa"]`.
    public var amr: [String] { raw["amr"]?.arrayValue?.compactMap(\.stringValue) ?? [] }
    /// Present when the sign-in met the multi-factor policy (a PAPE URI).
    public var acr: String? { raw["acr"]?.stringValue }

    /// Any other claim, by name.
    public subscript(claim: String) -> JSONValue? { raw[claim] }
}

/// What `signOut` managed (§10.4). The local session is gone in every case —
/// `signOut` throws only when the store itself could not be cleared.
public struct SignOutResult: Sendable, Equatable {
    public enum Revocation: Sendable, Equatable {
        /// The server revoked the refresh token, and with it the family.
        case revoked
        /// Revocation failed, or could not be attempted because the stored
        /// record could not be read (`.storage`); the refresh token stays live
        /// on the server until it expires (thirty days after sign-in by default).
        /// Worth logging.
        case failed(ProtelesAuthError)
        /// There was no refresh token to revoke: no session, or one from a
        /// client without the refresh_token grant.
        case notAttempted
    }

    public enum EndSession: Sendable, Equatable {
        /// No browser was passed, so the browser session is still live and the
        /// next sign-in may complete without asking for credentials.
        case notRequested
        /// The server redirected to `postLogoutRedirectURI` with our `state`.
        case completed
        /// The user closed the browser. Without a `postLogoutRedirectURI`
        /// this is how it always ends, and whether they confirmed first is
        /// not observable.
        case dismissed
        case failed(ProtelesAuthError)
    }

    public let revocation: Revocation
    public let endSession: EndSession
}
