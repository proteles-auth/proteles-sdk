import Foundation

/// How the SDK reaches one tenant as one app (docs/mobile-SDKs.md §10.1).
///
/// Everything the server would refuse later is refused here, at construction,
/// so a misconfigured app fails on its first launch rather than on a user's
/// first sign-in.
public struct ProtelesConfiguration: Sendable, Equatable {
    /// The tenant's issuer, exactly as the server spells it. It is compared
    /// byte for byte with discovery, the callback's `iss` and the ID token's
    /// `iss` — `https://auth.example.com/` is a different issuer from
    /// `https://auth.example.com` (§5.2 rule 2).
    public let issuer: String

    /// The app's `client_id`: one per app, registered by the tenant's
    /// administrator as a public client (`token_endpoint_auth_method: none`).
    public let clientId: String

    /// The redirect URI registered for the client, sent unchanged at the
    /// authorization and token endpoints: an `https` Universal Link, on a
    /// domain whose `apple-app-site-association` names this app. Never a
    /// private-use scheme, which the server does not register (M7), and never
    /// `http`, loopback included (§10.1).
    public let redirectURI: String

    /// The scopes to request. Must include `openid`: the SDK's user record is
    /// the verified ID token.
    public let scopes: [String]

    /// Where the browser returns after an optional end-session (§10.4). Held
    /// to the same rules as `redirectURI`, and registered separately on the
    /// client.
    public let postLogoutRedirectURI: String?

    /// A Keychain access group to share the session with the app's extensions.
    public let keychainAccessGroup: String?

    /// An App Group identifier. When set, refreshes are serialised across
    /// every process of the app with `flock` on a file in the group container
    /// (§10.6); without one, only within this process.
    public let appGroupIdentifier: String?

    /// `openid profile email` — the TypeScript SDK's default.
    public static let defaultScopes = ["openid", "profile", "email"]

    /// - Throws: `ProtelesAuthError.configuration` naming the first rule the
    ///   values break.
    public init(
        issuer: String,
        clientId: String,
        redirectURI: String,
        scopes: [String] = ProtelesConfiguration.defaultScopes,
        postLogoutRedirectURI: String? = nil,
        keychainAccessGroup: String? = nil,
        appGroupIdentifier: String? = nil
    ) throws {
        try Self.validateIssuer(issuer)
        guard !clientId.isEmpty, clientId.utf8.allSatisfy(Self.isVisibleASCII) else {
            throw ProtelesAuthError.configuration("clientId must be non-empty visible ASCII")
        }
        try Self.validateRedirect(redirectURI, role: "redirectURI")
        if let postLogoutRedirectURI {
            try Self.validateRedirect(postLogoutRedirectURI, role: "postLogoutRedirectURI")
        }
        guard !scopes.isEmpty else {
            throw ProtelesAuthError.configuration("scopes must not be empty")
        }
        // ASCII only (checked below), so `Set`'s canonical equivalence is
        // byte equality here.
        guard Set(scopes).count == scopes.count else {
            throw ProtelesAuthError.configuration("scopes must not repeat")
        }
        for scope in scopes {
            guard !scope.isEmpty, scope.utf8.allSatisfy(Self.isScopeCharacter) else {
                throw ProtelesAuthError.configuration("scope \"\(scope)\" is not a single RFC 6749 scope token")
            }
        }
        guard scopes.contains("openid") else {
            throw ProtelesAuthError.configuration("scopes must include \"openid\": the SDK verifies the ID token and keeps its claims as the user record")
        }
        if let keychainAccessGroup, keychainAccessGroup.isEmpty {
            throw ProtelesAuthError.configuration("keychainAccessGroup must be nil or non-empty")
        }
        if let appGroupIdentifier, appGroupIdentifier.isEmpty {
            throw ProtelesAuthError.configuration("appGroupIdentifier must be nil or non-empty")
        }

        self.issuer = issuer
        self.clientId = clientId
        self.redirectURI = redirectURI
        self.scopes = scopes
        self.postLogoutRedirectURI = postLogoutRedirectURI
        self.keychainAccessGroup = keychainAccessGroup
        self.appGroupIdentifier = appGroupIdentifier
    }

    /// The Keychain service the session lives under (§10.5).
    public var keychainService: String { "com.proteles.auth.\(clientId)" }

    var redirectURL: URL { URL(string: redirectURI)! }
    var postLogoutRedirectURL: URL? { postLogoutRedirectURI.flatMap(URL.init(string:)) }
    var scopeString: String { scopes.joined(separator: " ") }

    /// Discovery's URL: the issuer with `/.well-known/openid-configuration`
    /// appended, after removing one terminating `/` (OpenID Connect
    /// Discovery §4.1).
    var discoveryURL: URL {
        var base = issuer
        if base.hasSuffix("/") { base.removeLast() }
        return URL(string: base + "/.well-known/openid-configuration")!
    }

    /// Whether the issuer is plain `http` on loopback — a development server.
    /// Construction admits `http` only there, spelled in lower case.
    var issuerIsLoopbackHTTP: Bool {
        URLComponents(string: issuer)?.scheme == "http"
    }

    // MARK: - The rules

    /// Plain `http` is allowed for an issuer on loopback only — a development
    /// server; the repository's own end-to-end suite runs at
    /// `http://localhost:PORT`. Never for a redirect URI (§10.1). Compared as
    /// spelled: `LOCALHOST` is not in it. (`::1` is how older Foundation
    /// versions report the bracketed literal's host.)
    static let loopbackIssuerHosts: Set<String> = ["127.0.0.1", "::1", "[::1]", "localhost"]

    static func isVisibleASCII(_ byte: UInt8) -> Bool { byte > 0x20 && byte < 0x7F }

    /// RFC 6749 §3.3: `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )`.
    static func isScopeCharacter(_ byte: UInt8) -> Bool {
        byte == 0x21 || (0x23...0x5B).contains(byte) || (0x5D...0x7E).contains(byte)
    }

    static func validateIssuer(_ issuer: String) throws {
        guard !issuer.isEmpty, issuer.utf8.allSatisfy(isVisibleASCII) else {
            throw ProtelesAuthError.configuration("issuer must be non-empty visible ASCII")
        }
        guard !issuer.contains("?"), !issuer.contains("#") else {
            throw ProtelesAuthError.configuration("issuer must not carry a query or a fragment")
        }
        guard let parts = URLComponents(string: issuer), let scheme = parts.scheme,
              let host = parts.host, !host.isEmpty else {
            throw ProtelesAuthError.configuration("issuer \"\(issuer)\" is not an absolute URL")
        }
        guard parts.user == nil, parts.password == nil else {
            throw ProtelesAuthError.configuration("issuer must not carry userinfo")
        }
        // The scheme, and a loopback host, exactly as the server spells them:
        // it emits one spelling, and discovery, the callback's `iss` and the
        // ID token's `iss` are compared byte for byte (§5.2 rule 2), so
        // `HTTPS://…` could only ever fail later. As the Android SDK does.
        switch scheme {
        case "https":
            return
        case "http" where loopbackIssuerHosts.contains(host):
            return
        case "http" where loopbackIssuerHosts.contains(host.lowercased()):
            throw ProtelesAuthError.configuration("issuer's loopback host must be spelled in lower case, as the server spells it")
        case _ where ["https", "http"].contains(scheme.lowercased()):
            throw ProtelesAuthError.configuration("issuer's scheme must be spelled in lower case, as the server spells it")
        default:
            throw ProtelesAuthError.configuration("issuer must be https (plain http only on loopback, for development)")
        }
    }

    /// The server's rule for a registrable redirect (docs/mobile-SDKs.md
    /// §2.1), narrowed as §10.1 says: **no
    /// `http` at all**. Not `localhost`, which gets no port exemption at the
    /// authorization endpoint (trap 1); and, as settled on 2026-09-25, not the
    /// loopback IP literals either — the server would register one, but
    /// `ASWebAuthenticationSession` cannot intercept it, so accepting it here
    /// would only move the failure to the first sign-in.
    ///
    /// **And no private-use scheme** (M7): the server
    /// registers none, since a second app can claim any of them. What is left
    /// is an `https` Universal Link.
    static func validateRedirect(_ uri: String, role: String) throws {
        guard !uri.isEmpty, uri.utf8.allSatisfy(isVisibleASCII) else {
            throw ProtelesAuthError.configuration("\(role) must be non-empty visible ASCII")
        }
        guard !uri.contains("#") else {
            throw ProtelesAuthError.configuration("\(role) must not carry a fragment (RFC 6749 §3.1.2)")
        }
        guard let colon = uri.firstIndex(of: ":") else {
            throw ProtelesAuthError.configuration("\(role) \"\(uri)\" has no scheme")
        }
        let scheme = uri[..<colon].lowercased()
        guard let first = scheme.utf8.first, (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(first),
              scheme.utf8.allSatisfy({ byte in
                  (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
                      || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
                      || byte == UInt8(ascii: "+") || byte == UInt8(ascii: "-") || byte == UInt8(ascii: ".")
              }) else {
            throw ProtelesAuthError.configuration("\(role) \"\(uri)\" has no valid scheme")
        }
        guard URL(string: uri) != nil, let parts = URLComponents(string: uri) else {
            throw ProtelesAuthError.configuration("\(role) \"\(uri)\" is not a URL")
        }

        switch scheme {
        case "https":
            guard let host = parts.host, !host.isEmpty else {
                throw ProtelesAuthError.configuration("\(role) \"\(uri)\" has no host")
            }
            guard parts.percentEncodedUser == nil, parts.percentEncodedPassword == nil else {
                throw ProtelesAuthError.configuration("\(role) must not carry userinfo")
            }
        case "http":
            let host = parts.host?.lowercased() ?? ""
            let instead = "use an https Universal Link on a domain whose apple-app-site-association names this app"
            if host == "localhost" {
                throw ProtelesAuthError.configuration(
                    "\(role) uses http://localhost, which gets no port exemption at /oauth/authorize (trap 1) and which ASWebAuthenticationSession cannot intercept; \(instead)")
            }
            if ["127.0.0.1", "::1", "[::1]"].contains(host) {
                throw ProtelesAuthError.configuration(
                    "\(role) is a loopback redirect, which ASWebAuthenticationSession cannot intercept and this SDK runs no listener for (§10.1); \(instead)")
            }
            throw ProtelesAuthError.configuration("\(role) may not use http, which anyone on the path can read (RFC 9700 §2.6); \(instead)")
        default:
            throw ProtelesAuthError.configuration(
                "\(role) \"\(uri)\" uses the private-use scheme \"\(scheme)\", which the server does not register: a second app can claim it (M7). "
                    + "Use an https Universal Link on a domain whose apple-app-site-association names this app")
        }
    }
}
