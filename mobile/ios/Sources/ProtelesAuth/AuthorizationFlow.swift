import Foundation

/// One authorization request and the secrets that bind its callback to it
/// (§10.2 steps 2–3).
struct AuthorizationRequest: Sendable, Equatable {
    let url: URL
    let state: String
    let nonce: String
    let pkce: PKCE

    /// A request with fresh `state`, `nonce` and PKCE from the system CSPRNG.
    static func make(endpoint: URL, configuration: ProtelesConfiguration) throws -> AuthorizationRequest {
        try make(
            endpoint: endpoint,
            configuration: configuration,
            state: SecureRandom.token(),
            nonce: SecureRandom.token(),
            pkce: PKCE.generate()
        )
    }

    /// Exactly the parameters §10.2 step 3 lists — and **no `login_hint`**,
    /// which the server does not honour (§6 P2.12).
    static func make(
        endpoint: URL,
        configuration: ProtelesConfiguration,
        state: String,
        nonce: String,
        pkce: PKCE
    ) throws -> AuthorizationRequest {
        let query = FormEncoding.encode([
            ("response_type", "code"),
            ("client_id", configuration.clientId),
            ("redirect_uri", configuration.redirectURI),
            ("scope", configuration.scopeString),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", pkce.challenge),
            ("code_challenge_method", pkce.method),
        ])
        guard let url = appendingQuery(query, to: endpoint) else {
            throw ProtelesAuthError.configuration("cannot build an authorization URL from \(endpoint.absoluteString)")
        }
        return AuthorizationRequest(url: url, state: state, nonce: nonce, pkce: pkce)
    }
}

/// The browser's return to the redirect URI (§10.2 step 4).
enum AuthorizationCallback {
    /// The authorization code, once the callback has proved it belongs to
    /// this sign-in and this issuer. In order:
    ///
    /// 0. it must be addressed to `redirectURI` — scheme, authority and path —
    ///    and its query must decode, every escape of it; otherwise it is not
    ///    a response to this request (`.stateMismatch`, as the Android SDK
    ///    reports it). `ASWebAuthenticationSession` matches the scheme only;
    /// 1. `state` must be present once and equal the one sent — before
    ///    anything else in the response is believed, including an error;
    /// 2. `iss` must be present once and equal the issuer byte for byte (RFC
    ///    9207: discovery advertises `authorization_response_iss_parameter_supported`,
    ///    so its absence is a refusal, not a server that predates it);
    /// 3. an `error` becomes `.authorization(error:description:errorURI:)`;
    /// 4. otherwise there must be exactly one non-empty `code`.
    static func code(from callback: URL, redirectURI: URL, expectedState: String, expectedIssuer: String) throws -> String {
        let fields = try parameters(of: callback, addressedTo: redirectURI)
        func values(_ name: String) -> [String] { fields.filter { $0.name == name }.map(\.value) }

        try checkState(fields, expectedState)

        let iss = values("iss")
        guard iss.count == 1, bytesEqual(iss[0], expectedIssuer) else {
            throw ProtelesAuthError.issuerMismatch(expected: expectedIssuer, received: iss.first)
        }

        let error = values("error")
        if let code = error.first {
            throw ProtelesAuthError.authorization(
                error: code,
                description: values("error_description").first,
                errorURI: values("error_uri").first
            )
        }

        let code = values("code")
        guard code.count == 1, !code[0].isEmpty else {
            throw ProtelesAuthError.authorization(
                error: "invalid_response",
                description: "the callback carried neither exactly one code nor an error",
                errorURI: nil
            )
        }
        return code[0]
    }

    /// The browser's return from `end_session_endpoint` (§10.4): addressed to
    /// the post-logout redirect URI, its query decoding, carrying the `state`
    /// that was sent exactly once.
    static func checkEndSessionReturn(_ callback: URL, redirectURI: URL, expectedState: String) throws {
        try checkState(parameters(of: callback, addressedTo: redirectURI), expectedState)
    }

    private static func checkState(_ fields: [(name: String, value: String)], _ expectedState: String) throws {
        let state = fields.filter { $0.name == "state" }.map(\.value)
        guard !expectedState.isEmpty, state.count == 1, bytesEqual(state[0], expectedState) else {
            throw ProtelesAuthError.stateMismatch
        }
    }

    /// The callback's query, once it is known to be addressed to
    /// `redirectURI` and to decode. The scheme is compared ignoring case (RFC
    /// 3986 §3.1); the authority and path as spelled, as the Android SDK
    /// compares them.
    private static func parameters(of callback: URL, addressedTo redirectURI: URL) throws -> [(name: String, value: String)] {
        guard let got = URLComponents(url: callback, resolvingAgainstBaseURL: false),
              let want = URLComponents(url: redirectURI, resolvingAgainstBaseURL: false),
              let scheme = got.scheme, scheme.lowercased() == want.scheme?.lowercased(),
              got.percentEncodedUser == want.percentEncodedUser,
              got.percentEncodedPassword == want.percentEncodedPassword,
              got.percentEncodedHost == want.percentEncodedHost,
              got.port == want.port,
              got.percentEncodedPath == want.percentEncodedPath,
              let fields = FormEncoding.decodeExactly(got.percentEncodedQuery ?? "") else {
            throw ProtelesAuthError.stateMismatch
        }
        return fields
    }
}

/// RP-initiated logout (§10.4): the URL that sends the browser to
/// `end_session_endpoint`.
enum EndSessionRequest {
    static func url(
        endpoint: URL,
        idTokenHint: String?,
        clientId: String,
        postLogoutRedirectURI: String?,
        state: String
    ) -> URL? {
        var fields: [(String, String)] = []
        if let idTokenHint { fields.append(("id_token_hint", idTokenHint)) }
        fields.append(("client_id", clientId))
        if let postLogoutRedirectURI { fields.append(("post_logout_redirect_uri", postLogoutRedirectURI)) }
        // Always, as §10.4 lists it and the Android SDK sends it — even when
        // there is no return to check it on.
        fields.append(("state", state))
        return appendingQuery(FormEncoding.encode(fields), to: endpoint)
    }
}

/// `endpoint` with `query` appended to whatever query it already has.
func appendingQuery(_ query: String, to endpoint: URL) -> URL? {
    guard var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false) else { return nil }
    if let existing = components.percentEncodedQuery, !existing.isEmpty {
        components.percentEncodedQuery = existing + "&" + query
    } else {
        components.percentEncodedQuery = query
    }
    return components.url
}
