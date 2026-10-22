import Foundation

/// A successful token-endpoint response.
struct TokenResponse: Sendable, Equatable {
    let accessToken: String
    let expiresIn: TimeInterval
    let refreshToken: String?
    let idToken: String?
    let scope: String?
}

/// A `200` from the refresh grant whose body is a JSON object, not yet checked
/// any further (§10.9 item 5). The server spent the presented refresh token
/// before it answered, so the one in this body is the family's only live
/// credential: the caller persists `refreshToken` first, and only then calls
/// `checked()`, which may refuse the rest of the body.
struct UncheckedTokenResponse: Sendable {
    let body: [String: JSONValue]

    /// The rotated refresh token, when the body carries a non-empty string.
    var refreshToken: String? {
        guard let token = body["refresh_token"]?.stringValue, !token.isEmpty else { return nil }
        return token
    }

    func checked() throws -> TokenResponse {
        try TokenClient.parse(object: body)
    }
}

/// The token and revocation endpoints, for a public client (§10.2 step 5,
/// §10.3, §10.4). No client secret, ever: a native app is a public client and
/// identifies itself with `client_id` in the body.
struct TokenClient: Sendable {
    let transport: any HTTPTransport
    let clientId: String
    let now: @Sendable () -> Date
    /// The client's: a 429 from here closes it, and no token request is sent
    /// while it is closed (§10.9 item 3).
    let gate: RateLimitGate

    init(transport: any HTTPTransport, clientId: String, now: @escaping @Sendable () -> Date, gate: RateLimitGate? = nil) {
        self.transport = transport
        self.clientId = clientId
        self.now = now
        self.gate = gate ?? RateLimitGate(now: now)
    }

    /// `grant_type=authorization_code`, with the redirect URI identical to the
    /// one sent to the authorization endpoint. Returned unchecked, like a
    /// refresh, so a refresh token in a body that is then refused can still be
    /// revoked (§10.9 item 7).
    func exchangeCode(endpoint: URL, code: String, redirectURI: String, codeVerifier: String) async throws -> UncheckedTokenResponse {
        try await tokenResponseBody(endpoint, [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirectURI),
            ("client_id", clientId),
            ("code_verifier", codeVerifier),
        ])
    }

    /// `grant_type=refresh_token`. Returns the body unchecked beyond being a
    /// JSON object, so the caller can persist the rotated refresh token before
    /// anything else in it can be refused (§10.9 item 5).
    func refresh(endpoint: URL, refreshToken: String) async throws -> UncheckedTokenResponse {
        try await tokenResponseBody(endpoint, [
            ("grant_type", "refresh_token"),
            ("refresh_token", refreshToken),
            ("client_id", clientId),
        ])
    }

    /// RFC 7009 revocation of a refresh token. Succeeds on `200`; anything
    /// else throws, and the caller decides what that means (sign-out clears
    /// the session regardless).
    func revoke(endpoint: URL, refreshToken: String) async throws {
        let response = try await post(endpoint, [
            ("token", refreshToken),
            ("token_type_hint", "refresh_token"),
            ("client_id", clientId),
        ])
        guard response.status == 200 else { throw refusal(response, from: endpoint) }
    }

    // MARK: - Internals

    private func post(_ endpoint: URL, _ fields: [(String, String)]) async throws -> HTTPResponse {
        let request = HTTPRequest(
            method: "POST",
            url: endpoint,
            headers: [
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            ],
            body: Data(FormEncoding.encode(fields).utf8)
        )
        do {
            return try await transport.send(request)
        } catch {
            throw asProtelesError(error)
        }
    }

    private func tokenResponseBody(_ endpoint: URL, _ fields: [(String, String)]) async throws -> UncheckedTokenResponse {
        // A request into a latched bucket keeps it latched (§2.5): honouring
        // Retry-After means not sending — the code exchange included, which a
        // refresh's 429 can close the gate on while the browser is showing.
        if let wait = gate.remaining() { throw ProtelesAuthError.rateLimited(retryAfter: wait) }
        let response = try await post(endpoint, fields)
        guard response.status == 200 else { throw refusal(response, from: endpoint) }
        guard let body = JSONValue.parseObject(response.body) else {
            throw Self.malformed("the token response is not a JSON object")
        }
        return UncheckedTokenResponse(body: body)
    }

    /// A non-200 answer as the error a caller acts on: `429` closes the gate
    /// for its `Retry-After`; any 5xx is an outage (`.network`, retryable — a
    /// deploy, a gateway, `server_error` or `temporarily_unavailable` alike),
    /// as discovery and the key set already do; otherwise the OAuth error from
    /// the body, which will not change by asking again — `nil` when the body
    /// names none, never a code made up here.
    private func refusal(_ response: HTTPResponse, from endpoint: URL) -> ProtelesAuthError {
        if response.status == 429 { return gate.close(response) }
        let body = JSONValue.parseObject(response.body)
        let error = body?["error"]?.stringValue
        let description = body?["error_description"]?.stringValue
        if response.status >= 500 {
            let detail = error.map { " (\($0)\(description.map { ": \($0)" } ?? ""))" } ?? ""
            return .network("\(endpoint.absoluteString) answered HTTP \(response.status)\(detail)", status: response.status)
        }
        return .tokenEndpoint(error: error, description: description, status: response.status)
    }

    static func malformed(_ why: String) -> ProtelesAuthError {
        .tokenEndpoint(error: "invalid_response", description: why, status: 200)
    }

    static func parse(_ data: Data) throws -> TokenResponse {
        guard let body = JSONValue.parseObject(data) else { throw malformed("the token response is not a JSON object") }
        return try parse(object: body)
    }

    static func parse(object body: [String: JSONValue]) throws -> TokenResponse {
        guard let accessToken = body["access_token"]?.stringValue, !accessToken.isEmpty else {
            throw malformed("the token response has no access_token")
        }
        guard let tokenType = body["token_type"]?.stringValue, tokenType.caseInsensitiveCompare("Bearer") == .orderedSame else {
            throw malformed("the token response's token_type is not Bearer")
        }
        // The server never sends 0 (it refuses to mint a token that
        // would expire as it is issued), and some libraries read 0 as "never
        // expires". The lifetime is whatever the server says — a SAML session
        // deadline shortens it — never an assumed fifteen minutes.
        guard let expiresIn = body["expires_in"]?.numberValue, expiresIn > 0, expiresIn.isFinite else {
            throw malformed("the token response has no positive expires_in")
        }
        // An optional member is absent (`null` counts), or a string — an empty
        // one read as absent. Anything else refuses the response, as the
        // Android SDK does: read as absent, a refresh_token the server sent
        // as a number would leave this client presenting the one it spent.
        func optionalString(_ name: String) throws -> String? {
            switch body[name] {
            case nil, .null?:
                return nil
            case .string(let value)?:
                return value.isEmpty ? nil : value
            default:
                throw malformed("the token response's \(name) is not a string")
            }
        }
        return TokenResponse(
            accessToken: accessToken,
            expiresIn: expiresIn,
            refreshToken: try optionalString("refresh_token"),
            idToken: try optionalString("id_token"),
            scope: try optionalString("scope")
        )
    }
}
