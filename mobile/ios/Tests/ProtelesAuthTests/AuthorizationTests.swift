import Foundation
import Testing
@testable import ProtelesAuth

@Suite("The authorization URL (§10.2 steps 2–3)")
struct AuthorizationURLTests {
    @Test func carriesExactlyTheContractsParametersInOrder() throws {
        let configuration = try Fixture.configuration()
        let pkce = PKCE(verifierBytes: Data(repeating: 7, count: 32))
        let request = try AuthorizationRequest.make(
            endpoint: URL(string: "https://auth.example.test/oauth/authorize")!,
            configuration: configuration,
            state: "state-1",
            nonce: "nonce-1",
            pkce: pkce
        )
        let items = queryItems(of: request.url)
        #expect(items.map(\.name) == [
            "response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
            "code_challenge", "code_challenge_method",
        ])
        #expect(items.map(\.value) == [
            "code", Fixture.clientId, Fixture.redirectURI, "openid profile email", "state-1", "nonce-1",
            pkce.challenge, "S256",
        ])
        #expect(!request.url.absoluteString.contains("login_hint"), "the server ignores it (§6 P2.12)")
        #expect(request.url.absoluteString.hasPrefix("https://auth.example.test/oauth/authorize?response_type=code&"))
        // The redirect URI and the scope are percent-encoded, never raw.
        #expect(request.url.absoluteString.contains("redirect_uri=https%3A%2F%2Fmobile.example.com%2Foauth%2Fcallback"))
        #expect(request.url.absoluteString.contains("scope=openid%20profile%20email"))
    }

    @Test func freshSecretsEveryTime() throws {
        let configuration = try Fixture.configuration()
        let endpoint = URL(string: "https://auth.example.test/oauth/authorize")!
        let a = try AuthorizationRequest.make(endpoint: endpoint, configuration: configuration)
        let b = try AuthorizationRequest.make(endpoint: endpoint, configuration: configuration)
        #expect(a.state.count == 43 && a.nonce.count == 43 && a.pkce.verifier.count == 43)
        #expect(a.state != b.state && a.nonce != b.nonce && a.pkce != b.pkce && a.state != a.nonce)
    }

    @Test func keepsAQueryTheEndpointAlreadyHas() throws {
        let request = try AuthorizationRequest.make(
            endpoint: URL(string: "https://auth.example.test/oauth/authorize?tenant=acme")!,
            configuration: Fixture.configuration(),
            state: "s", nonce: "n", pkce: PKCE(verifierBytes: Data(count: 32))
        )
        #expect(queryItems(of: request.url).first?.name == "tenant")
        #expect(queryItems(of: request.url).count == 9)
    }
}

@Suite("The callback (§10.2 step 4)")
struct CallbackTests {
    private func parse(_ query: String, state: String = "state-1", target: String = Fixture.redirectURI) throws -> String {
        try AuthorizationCallback.code(
            from: URL(string: "\(target)?\(query)")!,
            redirectURI: URL(string: Fixture.redirectURI)!,
            expectedState: state,
            expectedIssuer: Fixture.issuer
        )
    }

    private let iss = "iss=https%3A%2F%2Fauth.example.test"

    @Test func aGoodCallbackYieldsTheCode() throws {
        #expect(try parse("code=abc&state=state-1&\(iss)") == "abc")
        #expect(try parse("\(iss)&state=state-1&code=a%2Bb") == "a+b", "order does not matter; escapes decode")
    }

    @Test func aStateMismatchIsRefusedBeforeAnythingElseIsBelieved() {
        #expect(throws: ProtelesAuthError.stateMismatch) { try parse("code=abc&state=other&\(iss)") }
        #expect(throws: ProtelesAuthError.stateMismatch) { try parse("code=abc&\(iss)") }
        #expect(throws: ProtelesAuthError.stateMismatch) { try parse("code=abc&state=state-1&state=state-1&\(iss)") }
        #expect(throws: ProtelesAuthError.stateMismatch) { try parse("code=abc&state=&\(iss)", state: "") }
        // An error response whose state is not ours is not the server's error.
        #expect(throws: ProtelesAuthError.stateMismatch) { try parse("error=access_denied&state=forged&\(iss)") }
    }

    @Test("a missing iss is a refusal (RFC 9207)")
    func missingIssuer() {
        #expect(throws: ProtelesAuthError.issuerMismatch(expected: Fixture.issuer, received: nil)) {
            try parse("code=abc&state=state-1")
        }
    }

    @Test("a wrong iss is a refusal, compared byte for byte")
    func wrongIssuer() {
        #expect(throws: ProtelesAuthError.issuerMismatch(expected: Fixture.issuer, received: "https://auth.example.test/")) {
            try parse("code=abc&state=state-1&iss=https%3A%2F%2Fauth.example.test%2F")
        }
        #expect(throws: ProtelesAuthError.issuerMismatch(expected: Fixture.issuer, received: "https://evil.example")) {
            try parse("code=abc&state=state-1&iss=https%3A%2F%2Fevil.example")
        }
        // Even an error response must come from our issuer.
        #expect(throws: ProtelesAuthError.issuerMismatch(expected: Fixture.issuer, received: nil)) {
            try parse("error=access_denied&state=state-1")
        }
    }

    @Test func anErrorResponseBecomesATypedAuthorizationError() {
        #expect(throws: ProtelesAuthError.authorization(error: "access_denied", description: "The user said no", errorURI: nil)) {
            try parse("error=access_denied&error_description=The+user+said+no&state=state-1&\(iss)")
        }
        #expect(throws: ProtelesAuthError.authorization(error: "invalid_scope", description: nil, errorURI: nil)) {
            try parse("error=invalid_scope&state=state-1&\(iss)")
        }
        #expect(throws: ProtelesAuthError.authorization(error: "access_denied", description: nil, errorURI: "https://auth.example.test/help#denied")) {
            try parse("error=access_denied&error_uri=https%3A%2F%2Fauth.example.test%2Fhelp%23denied&state=state-1&\(iss)")
        }
    }

    /// Escapes that are well-formed but decode to bytes that are not UTF-8.
    /// (`URL` itself re-escapes a malformed one such as `%zz` or a lone `%`
    /// into `%25zz` on current Foundation, so those never reach the parser
    /// here; `FormEncodingTests` covers them on the string.)
    @Test(
        "a query with an escape that does not decode is refused whole: a second state, iss or code cannot hide behind it",
        arguments: [
            "code=abc&state=state-1&state=%FF&iss=https%3A%2F%2Fauth.example.test",
            "code=abc&state=state-1&iss=https%3A%2F%2Fauth.example.test&iss=%E9",
            "code=abc&code=%C3&state=state-1&iss=https%3A%2F%2Fauth.example.test",
        ]
    )
    func malformedEscapes(_ query: String) throws {
        // The positive control: the URL carries the escape as written, so
        // this is the parser's refusal and not the URL's rewriting.
        let url = try #require(URL(string: "\(Fixture.redirectURI)?\(query)"))
        #expect(URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedQuery == query)
        #expect(throws: ProtelesAuthError.stateMismatch) { try parse(query) }
    }

    @Test("a callback not addressed to the redirect URI — scheme, authority and path — is not a response to this request", arguments: [
        "https://other.example.com/oauth/callback",
        "https://mobile.example.com/oauth/other",
        "https://mobile.example.com/oauth/callback/",
        "https://mobile.example.com:8443/oauth/callback",
        "http://mobile.example.com/oauth/callback",
    ])
    func anotherTarget(_ target: String) {
        #expect(throws: ProtelesAuthError.stateMismatch, "\(target)") { try parse("code=abc&state=state-1&\(iss)", target: target) }
    }

    @Test("the scheme is compared ignoring case (RFC 3986 §3.1)")
    func schemeCase() throws {
        #expect(try parse("code=abc&state=state-1&\(iss)", target: "HTTPS://mobile.example.com/oauth/callback") == "abc")
    }

    @Test func noCodeOrTwoCodesIsRefused() {
        #expect(throws: ProtelesAuthError.self) { try parse("state=state-1&\(iss)") }
        #expect(throws: ProtelesAuthError.self) { try parse("code=&state=state-1&\(iss)") }
        #expect(throws: ProtelesAuthError.self) { try parse("code=a&code=b&state=state-1&\(iss)") }
    }

    @Test("a user cancelling the browser is its own outcome, and no code is redeemed")
    func userCancel() async throws {
        let server = StubServer()
        let client = try makeClient(server: server, store: SpyStore())
        await #expect(throws: ProtelesAuthError.cancelled) {
            _ = try await client.signIn(using: StubBrowser.cancels())
        }
        #expect(server.requests(to: "/oauth/token").isEmpty)
    }
}

@Suite("The end-session URL (§10.4)")
struct EndSessionURLTests {
    @Test func carriesTheHintClientRedirectAndState() throws {
        let url = try #require(EndSessionRequest.url(
            endpoint: URL(string: "https://auth.example.test/oauth/logout")!,
            idTokenHint: "h.p.s",
            clientId: Fixture.clientId,
            postLogoutRedirectURI: Fixture.postLogoutRedirectURI,
            state: "st"
        ))
        #expect(queryItems(of: url).map(\.name) == ["id_token_hint", "client_id", "post_logout_redirect_uri", "state"])
        #expect(queryItems(of: url).map(\.value) == ["h.p.s", Fixture.clientId, Fixture.postLogoutRedirectURI, "st"])
    }

    @Test("state is sent even without a redirect to return it on (§10.4), as the Android SDK sends it")
    func stateWithoutARedirect() throws {
        let url = try #require(EndSessionRequest.url(
            endpoint: URL(string: "https://auth.example.test/oauth/logout")!,
            idTokenHint: nil, clientId: Fixture.clientId, postLogoutRedirectURI: nil, state: "st"
        ))
        #expect(queryItems(of: url).map(\.name) == ["client_id", "state"])
    }
}
