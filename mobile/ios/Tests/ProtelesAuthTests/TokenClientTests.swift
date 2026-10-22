import Foundation
import Testing
@testable import ProtelesAuth

@Suite("The token client against a stub transport")
struct TokenClientTests {
    private let endpoint = URL(string: "https://auth.example.test/oauth/token")!

    private func client(_ server: StubServer) -> TokenClient {
        TokenClient(transport: server, clientId: Fixture.clientId, now: { Fixture.t0 })
    }

    @Test("code exchange: a public client's form, no secret")
    func codeExchange() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .tokens(access: "at", refresh: "rt", idToken: "h.p.s", expiresIn: 600) }
        let response = try await client(server).exchangeCode(
            endpoint: endpoint, code: "c+1", redirectURI: Fixture.redirectURI, codeVerifier: "v"
        ).checked()
        #expect(response == TokenResponse(accessToken: "at", expiresIn: 600, refreshToken: "rt", idToken: "h.p.s", scope: "openid profile email"))

        let request = try #require(server.requests.first)
        #expect(request.method == "POST")
        #expect(request.headers["Content-Type"] == "application/x-www-form-urlencoded")
        #expect(request.headers["Authorization"] == nil, "a public client has no secret to send")
        #expect(request.formFields.map(\.name) == ["grant_type", "code", "redirect_uri", "client_id", "code_verifier"])
        #expect(request.form == [
            "grant_type": "authorization_code", "code": "c+1", "redirect_uri": Fixture.redirectURI,
            "client_id": Fixture.clientId, "code_verifier": "v",
        ])
        #expect(request.bodyString?.contains("code=c%2B1") == true, "a + in a value is escaped, never read as a space")
    }

    @Test func refreshForm() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .tokens(access: "at2", refresh: "rt2", idToken: nil) }
        _ = try await client(server).refresh(endpoint: endpoint, refreshToken: "rt1")
        let request = try #require(server.requests.first)
        #expect(request.formFields.map(\.name) == ["grant_type", "refresh_token", "client_id"])
        #expect(request.form == ["grant_type": "refresh_token", "refresh_token": "rt1", "client_id": Fixture.clientId])
    }

    @Test func revocationForm() async throws {
        let server = StubServer()
        try await client(server).revoke(endpoint: URL(string: "https://auth.example.test/oauth/revoke")!, refreshToken: "rt1")
        let request = try #require(server.requests.first)
        #expect(request.url.path == "/oauth/revoke")
        #expect(request.form == ["token": "rt1", "token_type_hint": "refresh_token", "client_id": Fixture.clientId])
    }

    @Test func anOAuthErrorBodyIsTyped() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("invalid_grant", description: "spent", status: 400) }
        await #expect(throws: ProtelesAuthError.tokenEndpoint(error: "invalid_grant", description: "spent", status: 400)) {
            _ = try await client(server).refresh(endpoint: endpoint, refreshToken: "rt")
        }
    }

    @Test("a refusal whose body names no OAuth error carries none — never one made up from the status")
    func aRefusalWithoutAnOAuthError() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in HTTPResponse(status: 403, body: Data("<html>forbidden</html>".utf8)) }
        await #expect(throws: ProtelesAuthError.tokenEndpoint(error: nil, description: nil, status: 403)) {
            _ = try await client(server).refresh(endpoint: endpoint, refreshToken: "rt")
        }
        #expect(ProtelesAuthError.tokenEndpoint(error: nil, description: nil, status: 403).localizedDescription.contains("HTTP 403"))
    }

    @Test(
        "any 5xx is an outage (.network, retryable), with or without an OAuth error body",
        arguments: [
            HTTPResponse(status: 502, body: Data("<html>bad gateway</html>".utf8)),
            HTTPResponse.oauthError("server_error", status: 500),
            HTTPResponse.oauthError("temporarily_unavailable", status: 503),
        ]
    )
    func anOutageIsANetworkError(_ response: HTTPResponse) async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in response }
        server.on("/oauth/revoke") { _ in response }
        for attempt in [
            { try await self.client(server).exchangeCode(endpoint: self.endpoint, code: "c", redirectURI: Fixture.redirectURI, codeVerifier: "v") } as @Sendable () async throws -> Any,
            { try await self.client(server).refresh(endpoint: self.endpoint, refreshToken: "rt") },
            { try await self.client(server).revoke(endpoint: URL(string: "https://auth.example.test/oauth/revoke")!, refreshToken: "rt") },
        ] {
            do {
                _ = try await attempt()
                Issue.record("expected a network error")
            } catch ProtelesAuthError.network(let message, let status) {
                #expect(message.contains("HTTP \(response.status)"))
                #expect(status == response.status, "the network error carries the status (§10.9 item 4)")
            } catch {
                Issue.record("expected a network error, got \(error)")
            }
        }
    }

    @Test("429 carries Retry-After, in seconds or as an HTTP-date")
    func rateLimited() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("slow_down", status: 429, headers: ["Retry-After": "30"]) }
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 30)) {
            _ = try await client(server).refresh(endpoint: endpoint, refreshToken: "rt")
        }
        server.on("/oauth/token") { _ in HTTPResponse(status: 429, headers: ["retry-after": "Fri, 15 Jan 2027 08:00:45 GMT"]) }
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 45)) {
            _ = try await client(server).refresh(endpoint: endpoint, refreshToken: "rt")
        }
        server.on("/oauth/token") { _ in HTTPResponse(status: 429) }
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 60), "none it can read: the sixty seconds it waits") {
            _ = try await client(server).refresh(endpoint: endpoint, refreshToken: "rt")
        }
    }

    @Test("after a 429 no token request is sent — the code exchange included — until Retry-After; revocation still is")
    func aClosedGateSendsNoTokenRequest() async throws {
        let clock = TestClock()
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("slow_down", status: 429, headers: ["Retry-After": "30"]) }
        let tokens = TokenClient(transport: server, clientId: Fixture.clientId, now: clock.function)
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 30)) {
            _ = try await tokens.refresh(endpoint: endpoint, refreshToken: "rt")
        }
        server.on("/oauth/token") { _ in .tokens(access: "at", refresh: "rt2", idToken: nil) }
        clock.advance(10)
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 20)) {
            _ = try await tokens.exchangeCode(endpoint: endpoint, code: "c", redirectURI: Fixture.redirectURI, codeVerifier: "v")
        }
        #expect(server.requests(to: "/oauth/token").count == 1, "nothing sent into the latched bucket")
        try await tokens.revoke(endpoint: URL(string: "https://auth.example.test/oauth/revoke")!, refreshToken: "rt")
        clock.advance(20)
        _ = try await tokens.exchangeCode(endpoint: endpoint, code: "c", redirectURI: Fixture.redirectURI, codeVerifier: "v")
        #expect(server.requests(to: "/oauth/token").count == 2)
    }

    @Test func aTransportFailureIsANetworkError() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in throw URLError(.notConnectedToInternet) }
        do {
            _ = try await client(server).refresh(endpoint: endpoint, refreshToken: "rt")
            Issue.record("expected a network error")
        } catch ProtelesAuthError.network {
        } catch {
            Issue.record("expected a network error, got \(error)")
        }
    }

    @Test(arguments: [
        (#"{"token_type":"Bearer","expires_in":900}"#, "no access_token"),
        (#"{"access_token":"","token_type":"Bearer","expires_in":900}"#, "empty access_token"),
        (#"{"access_token":"a","token_type":"MAC","expires_in":900}"#, "not Bearer"),
        (#"{"access_token":"a","expires_in":900}"#, "no token_type"),
        (#"{"access_token":"a","token_type":"Bearer","expires_in":0}"#, "expires_in 0 is not 'never expires'"),
        (#"{"access_token":"a","token_type":"Bearer"}"#, "no expires_in"),
        (#"{"access_token":"a","token_type":"Bearer","expires_in":"900"}"#, "expires_in as a string"),
        (#"[]"#, "not an object"),
    ])
    func aMalformedSuccessIsRefused(_ body: String, _ why: String) {
        #expect(throws: ProtelesAuthError.self, "\(why)") { _ = try TokenClient.parse(Data(body.utf8)) }
    }

    @Test("a refresh answer is handed back before it is checked, so the rotation can be saved first (§10.9 item 5)")
    func refreshIsUncheckedUntilAsked() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .json(.object(["refresh_token": .string("rt2"), "token_type": .string("MAC")])) }
        let answer = try await client(server).refresh(endpoint: endpoint, refreshToken: "rt1")
        #expect(answer.refreshToken == "rt2")
        #expect(throws: ProtelesAuthError.self) { _ = try answer.checked() }

        server.on("/oauth/token") { _ in HTTPResponse(status: 200, body: Data("not json".utf8)) }
        await #expect(throws: ProtelesAuthError.tokenEndpoint(error: "invalid_response", description: "the token response is not a JSON object", status: 200)) {
            _ = try await client(server).refresh(endpoint: endpoint, refreshToken: "rt1")
        }
        server.on("/oauth/token") { _ in .json(.object(["refresh_token": .string("")])) }
        #expect(try await client(server).refresh(endpoint: endpoint, refreshToken: "rt1").refreshToken == nil)
    }

    @Test("a token response naming a member twice is not a JSON object this SDK reads")
    func duplicateMembersInATokenResponse() {
        let body = #"{"access_token":"a","token_type":"Bearer","expires_in":60,"refresh_token":"r1","refresh_token":"r2"}"#
        #expect(throws: ProtelesAuthError.tokenEndpoint(error: "invalid_response", description: "the token response is not a JSON object", status: 200)) {
            _ = try TokenClient.parse(Data(body.utf8))
        }
    }

    @Test("an optional member that is not a string refuses the response; an empty one, or null, is absent", arguments: [
        (#""refresh_token":5"#, false),
        (#""refresh_token":["r"]"#, false),
        (#""id_token":{}"#, false),
        (#""id_token":true"#, false),
        (#""scope":["openid"]"#, false),
        (#""refresh_token":null,"id_token":null,"scope":null"#, true),
        (#""refresh_token":"","id_token":"","scope":"""#, true),
    ])
    func optionalMembers(_ members: String, _ accepted: Bool) throws {
        let body = Data(#"{"access_token":"a","token_type":"Bearer","expires_in":60,\#(members)}"#.utf8)
        if accepted {
            let response = try TokenClient.parse(body)
            #expect(response.refreshToken == nil && response.idToken == nil && response.scope == nil)
        } else {
            do {
                _ = try TokenClient.parse(body)
                Issue.record("\(members) was accepted")
            } catch ProtelesAuthError.tokenEndpoint(error: "invalid_response", let description, status: 200) {
                #expect(description?.contains("is not a string") == true)
            }
        }
    }

    @Test func bearerIsCaseInsensitiveAndAnEmptyRefreshTokenIsNone() throws {
        let response = try TokenClient.parse(Data(#"{"access_token":"a","token_type":"bearer","expires_in":60,"refresh_token":""}"#.utf8))
        #expect(response.expiresIn == 60)
        #expect(response.refreshToken == nil)
    }
}

@Suite("Discovery (§10.2 step 1)")
struct DiscoveryTests {
    @Test("discovery's issuer must equal the configured one byte for byte")
    func issuerMismatch() async throws {
        let server = StubServer(discoveryIssuer: "https://auth.example.test/")
        let client = try makeClient(server: server, store: SpyStore())
        let browser = StubBrowser.signsIn()
        await #expect(throws: ProtelesAuthError.issuerMismatch(expected: Fixture.issuer, received: "https://auth.example.test/")) {
            _ = try await client.signIn(using: browser)
        }
        #expect(browser.openedURLs.isEmpty, "the browser never opens against an unverified issuer")
    }

    @Test("a 5xx from discovery is the network error, carrying the status")
    func anOutage() async throws {
        let server = StubServer()
        server.on("/.well-known/openid-configuration") { _ in HTTPResponse(status: 502) }
        let client = try makeClient(server: server, store: SpyStore())
        do {
            _ = try await client.signIn(using: StubBrowser.signsIn())
            Issue.record("expected a network error")
        } catch ProtelesAuthError.network(_, let status) {
            #expect(status == 502)
        }
    }

    @Test func aCleartextEndpointIsRefused() throws {
        let document = #"{"issuer":"https://auth.example.test","authorization_endpoint":"http://auth.example.test/oauth/authorize","token_endpoint":"https://auth.example.test/oauth/token","jwks_uri":"https://auth.example.test/jwks"}"#
        #expect(throws: ProtelesAuthError.self) {
            _ = try DiscoveryDocument.parse(Data(document.utf8), configuration: Fixture.configuration())
        }
    }

    /// A discovery document for `issuer`, with `changes` applied (`nil`
    /// removes a member).
    private func document(issuer: String, _ changes: [String: JSONValue?] = [:]) -> Data {
        var members: [String: JSONValue] = [
            "issuer": .string(issuer),
            "authorization_endpoint": .string("\(issuer)/oauth/authorize"),
            "token_endpoint": .string("\(issuer)/oauth/token"),
            "jwks_uri": .string("\(issuer)/.well-known/jwks.json"),
            "revocation_endpoint": .string("\(issuer)/oauth/revoke"),
        ]
        for (name, value) in changes { members[name] = value }
        return TestSigner.encode(.object(members))
    }

    @Test("a loopback issuer's http endpoints must be on loopback too: never a cleartext hop to another host", arguments: [
        "http://auth.example.test/oauth/token",
        "http://10.0.0.5:8080/oauth/token",
        "http://LOCALHOST:8080/oauth/token",
        "HTTP://localhost:8080/oauth/token",
    ])
    func aLoopbackIssuerStaysOnLoopback(_ tokenEndpoint: String) throws {
        let configuration = try Fixture.configuration(issuer: "http://localhost:8080")
        #expect(throws: ProtelesAuthError.self, "\(tokenEndpoint)") {
            _ = try DiscoveryDocument.parse(self.document(issuer: "http://localhost:8080", ["token_endpoint": .string(tokenEndpoint)]), configuration: configuration)
        }
    }

    @Test("loopback on any of its spellings: a server on 127.0.0.1 may name [::1] and localhost")
    func anyLoopbackHost() throws {
        let configuration = try Fixture.configuration(issuer: "http://127.0.0.1:8080")
        let parsed = try DiscoveryDocument.parse(document(issuer: "http://127.0.0.1:8080", [
            "token_endpoint": .string("http://[::1]:8080/oauth/token"),
            "jwks_uri": .string("http://localhost:8080/.well-known/jwks.json"),
        ]), configuration: configuration)
        #expect(parsed.tokenEndpoint.absoluteString == "http://[::1]:8080/oauth/token")
    }

    @Test("an endpoint that is not a string is refused, not read as absent; null is absent", arguments: [
        ("revocation_endpoint", JSONValue.number(5)),
        ("end_session_endpoint", JSONValue.bool(true)),
        ("token_endpoint", JSONValue.array([.string("https://auth.example.test/oauth/token")])),
    ])
    func aNonStringEndpoint(_ name: String, _ value: JSONValue) throws {
        #expect(throws: ProtelesAuthError.self, "\(name)") {
            _ = try DiscoveryDocument.parse(self.document(issuer: Fixture.issuer, [name: value]), configuration: Fixture.configuration())
        }
        let absent = try DiscoveryDocument.parse(document(issuer: Fixture.issuer, ["revocation_endpoint": .null]), configuration: Fixture.configuration())
        #expect(absent.revocationEndpoint == nil)
    }

    @Test("an endpoint with a fragment, or a scheme not spelled https, is refused", arguments: [
        "https://auth.example.test/oauth/token#x",
        "https://auth.example.test/oauth/token#",
        "HTTPS://auth.example.test/oauth/token",
    ])
    func fragmentOrScheme(_ tokenEndpoint: String) {
        #expect(throws: ProtelesAuthError.self, "\(tokenEndpoint)") {
            _ = try DiscoveryDocument.parse(self.document(issuer: Fixture.issuer, ["token_endpoint": .string(tokenEndpoint)]), configuration: Fixture.configuration())
        }
    }

    @Test func aLoopbackIssuerMayUseHTTPEndpoints() throws {
        let document = #"{"issuer":"http://localhost:8080","authorization_endpoint":"http://localhost:8080/oauth/authorize","token_endpoint":"http://localhost:8080/oauth/token","jwks_uri":"http://localhost:8080/.well-known/jwks.json"}"#
        let parsed = try DiscoveryDocument.parse(Data(document.utf8), configuration: Fixture.configuration(issuer: "http://localhost:8080"))
        #expect(parsed.tokenEndpoint.absoluteString == "http://localhost:8080/oauth/token")
        #expect(parsed.revocationEndpoint == nil)
    }

    @Test("cached for the life of the client: two sign-ins, one discovery")
    func cached() async throws {
        let signIn = SignInServer()
        let client = try makeClient(server: signIn.server, store: SpyStore())
        _ = try await client.signIn(using: signIn.browser())
        _ = try await client.signIn(using: signIn.browser())
        #expect(signIn.server.requests(to: "/.well-known/openid-configuration").count == 1)
        #expect(signIn.server.requests(to: "/.well-known/jwks.json").count == 1)
    }
}
