import Foundation
import Testing
@testable import ProtelesAuth

// Behaviour the cross-platform review of 2026-09-25 aligned with the Android
// SDK: a session bound to its configuration, one rate-limit gate for every
// endpoint, and the paths around them.

@Suite("A stored session belongs to the configuration that signed it in")
struct SessionBindingTests {
    /// A second tenant, or a second client, sharing the first one's record —
    /// as two configurations with one `clientId` share one Keychain service.
    static let others: [(issuer: String, clientId: String)] = [
        ("https://other.example.test", Fixture.clientId),
        (Fixture.issuer, "com.example.other"),
    ]

    @Test(
        "a session stored for another issuer or client is never handed out, refreshed or revoked here; sign-out deletes it, sign-in overwrites it",
        arguments: others
    )
    func anotherConfigurationsSession(_ other: (issuer: String, clientId: String)) async throws {
        let signIn = SignInServer()
        let store = SpyStore()
        let clock = TestClock()
        let a = try makeClient(server: signIn.server, store: store, clock: clock)
        _ = try await a.signIn(using: signIn.browser())

        let otherServer = StubServer(issuer: other.issuer)
        let configuration = try ProtelesConfiguration(issuer: other.issuer, clientId: other.clientId, redirectURI: Fixture.redirectURI)
        let b = try makeClient(server: otherServer, store: store, clock: clock, configuration: configuration)

        #expect(try await b.currentUser() == nil)
        #expect(try await a.currentUser()?.subject == Fixture.subject, "still the first configuration's")
        clock.advance(451) // past half-life: a refresh would be due
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await b.validAccessToken() }
        #expect(otherServer.requests.isEmpty, "the other configuration's refresh token went to no endpoint of this one")

        #expect(try await b.signOut().revocation == .notAttempted)
        #expect(otherServer.requests.isEmpty, "not to the revocation endpoint either")
        #expect(signIn.server.requests(to: "/oauth/revoke").isEmpty)
        #expect(store.session == nil, "deleted: the person asked to sign out here")
    }

    @Test("a sign-in overwrites another configuration's session, and names its own")
    func signInOverwrites() async throws {
        let store = SpyStore()
        var foreign = StoredSession.signedIn(refreshToken: "rt-other-tenant")
        foreign.issuer = "https://other.example.test"
        try store.write(foreign.encoded())
        let signIn = SignInServer()
        let client = try makeClient(server: signIn.server, store: store)
        #expect(try await client.currentUser() == nil)
        _ = try await client.signIn(using: signIn.browser())
        #expect(store.session?.issuer == Fixture.issuer && store.session?.clientId == Fixture.clientId)
        #expect(store.session?.refreshToken == "rt-1")
        #expect(signIn.server.requests(to: "/oauth/revoke").isEmpty, "the other tenant's token is not sent here")
    }

    @Test("a record from before sessions named their configuration is no session, and its refresh token is not revoked on a guess")
    func aRecordWithoutItsConfiguration() async throws {
        // The shape this SDK wrote before `issuer` and `clientId` were added.
        let old = #"{"accessToken":"at-old","accessTokenExpiresAt":1800000900,"accessTokenReceivedAt":1800000000,"claims":{"sub":"user-1"},"refreshToken":"rt-old","version":1}"#
        let server = StubServer()
        let store = InMemoryTokenStore(data: Data(old.utf8))
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        #expect(try await client.currentUser() == nil)
        clock.advance(451)
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(server.requests.isEmpty)
        guard case .failed(.storage) = try await client.signOut().revocation else {
            Issue.record("expected the token to be reported as not revoked")
            return
        }
        #expect(server.requests(to: "/oauth/revoke").isEmpty)
        #expect(try store.read() == nil)
    }
}

@Suite("One rate-limit gate for every endpoint (§10.9 items 3 and 8)")
struct RateLimitGateTests {
    @Test("a 429 from the key set during a refresh's ID-token check: the tokens are kept, and the client waits it out")
    func keySetDuringARefresh() async throws {
        let clock = TestClock()
        // Signed by a key the client has not fetched yet: the check asks the key set.
        let server = RefreshTests.rotatingServer(signer: .rotated, serverTime: clock.function)
        server.on("/.well-known/jwks.json") { _ in HTTPResponse(status: 429, headers: ["Retry-After": "120"]) }
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(451)
        #expect(try await client.validAccessToken() == "at-2", "the key set's 429 says nothing against the new tokens")
        #expect(store.session?.refreshToken == "rt-2")

        let browser = StubBrowser.signsIn()
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 120)) { _ = try await client.signIn(using: browser) }
        #expect(browser.openedURLs.isEmpty)
    }

    @Test("a 429 from revocation at sign-out: reported with the wait observed, and waited out")
    func revocation() async throws {
        let server = StubServer()
        server.on("/oauth/revoke") { _ in HTTPResponse(status: 429) }
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: server, store: store)
        #expect(try await client.signOut().revocation == .failed(.rateLimited(retryAfter: 60)), "sixty seconds, not nil")
        #expect(store.session == nil)
        let browser = StubBrowser.signsIn()
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 60)) { _ = try await client.signIn(using: browser) }
        #expect(browser.openedURLs.isEmpty)
    }

    @Test("a 429 from discovery at end-session is waited out too: the next sign-in does not ask again")
    func discoveryAtEndSession() async throws {
        let server = StubServer()
        server.on("/.well-known/openid-configuration") { _ in HTTPResponse(status: 429, headers: ["Retry-After": "30"]) }
        let client = try makeClient(
            server: server, store: SpyStore(),
            configuration: Fixture.configuration(postLogoutRedirectURI: Fixture.postLogoutRedirectURI)
        )
        let result = try await client.signOut(endSession: StubBrowser.cancels())
        #expect(result.endSession == .failed(.rateLimited(retryAfter: 30)))
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 30)) { _ = try await client.signIn(using: StubBrowser.signsIn()) }
        #expect(server.requests(to: "/.well-known/openid-configuration").count == 1)
    }

    @Test("a 429 that arrives while the browser is showing holds back the code exchange: the code is not sent into the latched bucket")
    func theCodeExchangeChecksTheGate() async throws {
        let signIn = SignInServer()
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let client = try makeClient(server: signIn.server, store: store, clock: clock)
        let browser = GatedBrowser(then: signIn.browser())
        let signingIn = Task { try await client.signIn(using: browser) }
        await browser.showing.wait()

        // While the user types, the app refreshes and is told to slow down.
        signIn.server.on("/oauth/token") { _ in .oauthError("slow_down", status: 429, headers: ["Retry-After": "30"]) }
        clock.advance(900)
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 30)) { _ = try await client.validAccessToken() }

        browser.release.open()
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 30)) { _ = try await signingIn.value }
        #expect(signIn.server.requests(to: "/oauth/token").count == 1, "only the refresh; the exchange was not sent")
    }
}

@Suite("Around the edges of sign-in and refresh")
struct EdgeTests {
    @Test("a key set that answers 404 at sign-in is the network error, not an ID-token rejection; what the exchange got is revoked")
    func keySetNotFoundAtSignIn() async throws {
        let signIn = SignInServer()
        signIn.server.on("/.well-known/jwks.json") { _ in HTTPResponse(status: 404) }
        let store = SpyStore()
        let client = try makeClient(server: signIn.server, store: store)
        do {
            _ = try await client.signIn(using: signIn.browser())
            Issue.record("expected a network error")
        } catch ProtelesAuthError.network(_, let status) {
            #expect(status == 404)
        }
        #expect(store.session == nil)
        #expect(signIn.server.requests(to: "/oauth/revoke").map { $0.form["token"] } == ["rt-1"])
    }

    @Test("at sign-in too, the access token's lifetime starts before the code exchange is sent")
    func signInLifetimeStartsBeforeTheExchange() async throws {
        let signIn = SignInServer()
        let clock = TestClock()
        signIn.exchangeHook.value = { clock.advance(20) }
        let store = SpyStore()
        let client = try makeClient(server: signIn.server, store: store, clock: clock)
        _ = try await client.signIn(using: signIn.browser())
        #expect(store.session?.accessTokenReceivedAt == Fixture.t0)
        #expect(store.session?.accessTokenExpiresAt == Fixture.t0.addingTimeInterval(900))
    }

    @Test("with only the in-process lock, the system suspending the app does not abandon a refresh already sent: the rotation is kept")
    func backgroundExpiryWithTheInProcessLock() async throws {
        let requestSent = Gate()
        let answer = Gate()
        let server = StubServer()
        server.on("/oauth/token") { _ in
            requestSent.open()
            await answer.wait()
            // Abandoned, this is where the response is lost.
            try Task.checkCancellation()
            return .tokens(access: "at-2", refresh: "rt-2", idToken: nil)
        }
        let activity = ManualActivity()
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock, backgroundActivity: activity)
        #expect(client.lockScope == .inProcess)
        clock.advance(500)

        let call = Task { try await client.validAccessToken() }
        await requestSent.wait()
        activity.expire()
        answer.open()
        #expect(try await call.value == "at-2")
        #expect(store.session?.refreshToken == "rt-2", "the new refresh token was not lost")
        #expect(activity.counts.ended == 1)
    }

    @Test("an empty id_token on a refresh is no ID token: the session goes on with its claims, rather than ending over a malformed token")
    func anEmptyRefreshIDToken() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in
            .json(.object([
                "access_token": .string("at-2"), "token_type": .string("Bearer"), "expires_in": .number(900),
                "refresh_token": .string("rt-2"), "id_token": .string(""),
            ]))
        }
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(451)
        #expect(try await client.validAccessToken() == "at-2")
        #expect(store.session?.refreshToken == "rt-2")
        #expect(store.session?.claims == StoredSession.signedIn().claims)
        #expect(server.requests(to: "/oauth/revoke").isEmpty)
    }
}

@Suite("The URLSession transport")
struct TransportTests {
    /// Answers every request with a body of the size the URL's last path
    /// component names, without a Content-Length unless the query asks.
    final class SizedBodies: URLProtocol, @unchecked Sendable {
        override class func canInit(with request: URLRequest) -> Bool { true }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
        override func startLoading() {
            let url = request.url!
            let size = Int(url.lastPathComponent) ?? 0
            var headers = ["Content-Type": "application/octet-stream"]
            if url.query == "length" { headers["Content-Length"] = String(size) }
            let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            let chunk = Data(repeating: 0x61, count: 64 * 1024)
            var sent = 0
            while sent < size {
                let n = min(chunk.count, size - sent)
                client?.urlProtocol(self, didLoad: chunk.prefix(n))
                sent += n
            }
            client?.urlProtocolDidFinishLoading(self)
        }
        override func stopLoading() {}
    }

    private func transport() -> URLSessionTransport {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [SizedBodies.self]
        return URLSessionTransport(session: URLSession(configuration: configuration))
    }

    @Test("a body up to 1 MiB is read whole; one byte more is the network error, with a Content-Length or without", arguments: ["", "?length"])
    func responseCap(_ query: String) async throws {
        let limit = URLSessionTransport.defaultMaximumResponseBytes
        #expect(limit == 1 << 20)
        let whole = try await transport().send(HTTPRequest(method: "GET", url: URL(string: "https://sdk.test/\(limit)\(query)")!))
        #expect(whole.body.count == limit)
        do {
            _ = try await transport().send(HTTPRequest(method: "GET", url: URL(string: "https://sdk.test/\(limit + 1)\(query)")!))
            Issue.record("expected the body to be refused")
        } catch ProtelesAuthError.network(let message, _) {
            #expect(message.contains("more than \(limit) bytes"), "\(message)")
        }
    }
}
