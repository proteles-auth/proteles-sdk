import Foundation
import Testing
@testable import ProtelesAuth

@Suite("Sign in (§10.2), end to end against stubs")
struct SignInTests {
    @Test func signsInVerifiesAndPersistsBeforeReturning() async throws {
        let signIn = SignInServer()
        let store = SpyStore()
        let client = try makeClient(server: signIn.server, store: store)
        let browser = signIn.browser()

        let user = try await client.signIn(using: browser)

        #expect(user.subject == Fixture.subject)
        #expect(user.email == "user-1@example.test")
        #expect(user.emailVerified == true)
        #expect(user.amr == ["pwd"])
        #expect(user.authTime == Fixture.t0)

        // The browser was sent exactly the contract's parameters.
        let authorize = try #require(browser.openedURLs.first)
        #expect(authorize.path == "/oauth/authorize")
        #expect(Set(queryItems(of: authorize).map(\.name)) == [
            "response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
            "code_challenge", "code_challenge_method",
        ])

        // The token request used the same redirect URI and a verifier that
        // hashes to the challenge the browser carried (the stub checks it).
        let token = try #require(signIn.server.requests(to: "/oauth/token").first)
        #expect(token.form["redirect_uri"] == authorize.query["redirect_uri"])
        #expect(token.form["code"] == "code-1")
        #expect(PKCE.challenge(for: token.form["code_verifier"] ?? "") == authorize.query["code_challenge"])

        // Persisted.
        let stored = try #require(store.session)
        #expect(stored.refreshToken == "rt-1")
        #expect(stored.accessToken == "at-1")
        #expect(stored.accessTokenExpiresAt == Fixture.t0.addingTimeInterval(900))
        #expect(try await client.currentUser() == user)
        #expect(try await client.validAccessToken() == "at-1")
    }

    @Test("an ID token minted for another sign-in's nonce is refused, nothing is stored, and the refresh token is revoked (§10.9 item 7)")
    func nonceMismatch() async throws {
        let signIn = SignInServer()
        signIn.idTokenNonceOverride = "a-nonce-from-another-login"
        let store = SpyStore()
        let client = try makeClient(server: signIn.server, store: store)
        await #expect(throws: ProtelesAuthError.idTokenRejected(.nonce)) {
            _ = try await client.signIn(using: signIn.browser())
        }
        #expect(store.session == nil)
        #expect(signIn.server.requests(to: "/oauth/revoke").map { $0.form["token"] } == ["rt-1"],
                "a thirty-day family nobody holds is ended")
    }

    @Test("no ID token is a refusal, and what the exchange got is revoked")
    func noIDTokenIsARefusal() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .tokens(access: "at-1", refresh: "rt-1", idToken: nil) }
        let client = try makeClient(server: server, store: SpyStore())
        await #expect(throws: ProtelesAuthError.idTokenRejected(.missing)) {
            _ = try await client.signIn(using: StubBrowser.signsIn())
        }
        #expect(server.requests(to: "/oauth/revoke").map { $0.form["token"] } == ["rt-1"])
    }

    @Test("a code-exchange answer refused as malformed still has its refresh token revoked, as the Android SDK does")
    func malformedExchangeRevokes() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in
            .json(.object(["access_token": .string("at-1"), "token_type": .string("MAC"), "expires_in": .number(900), "refresh_token": .string("rt-1")]))
        }
        let store = SpyStore()
        let client = try makeClient(server: server, store: store)
        do {
            _ = try await client.signIn(using: StubBrowser.signsIn())
            Issue.record("expected the response to be refused")
        } catch ProtelesAuthError.tokenEndpoint(error: "invalid_response", _, _) {
        }
        #expect(server.requests(to: "/oauth/revoke").map { $0.form["token"] } == ["rt-1"])
        #expect(store.session == nil)
    }

    @Test("a store that cannot be written after the exchange: the storage error, and the refresh token revoked (§10.9 item 7)")
    func storeUnwritableAtSignIn() async throws {
        let signIn = SignInServer()
        let store = SpyStore()
        store.failWrites = [1]
        let client = try makeClient(server: signIn.server, store: store)
        await #expect(throws: ProtelesAuthError.storage("simulated write failure")) {
            _ = try await client.signIn(using: signIn.browser())
        }
        #expect(signIn.server.requests(to: "/oauth/revoke").map { $0.form["token"] } == ["rt-1"])
    }

    @Test("§5.2's clock rules still apply at sign-in: a device clock half an hour ahead refuses the ID token")
    func signInJudgesTheClock() async throws {
        let signIn = SignInServer()
        let clock = TestClock()
        clock.advance(1800) // the server signs at Fixture.t0
        let client = try makeClient(server: signIn.server, store: SpyStore(), clock: clock)
        await #expect(throws: ProtelesAuthError.idTokenRejected(.expired)) {
            _ = try await client.signIn(using: signIn.browser())
        }
    }

    @Test("cancelling the caller once the code is being exchanged does not stop the sign-in (§10.9 item 7)")
    func cancelledDuringTheExchange() async throws {
        let signIn = SignInServer()
        let exchanging = Gate()
        let answer = Gate()
        signIn.exchangeHook.value = {
            exchanging.open()
            await answer.wait()
            // The task running the exchange, cancelled or not.
            try Task.checkCancellation()
        }
        let store = SpyStore()
        let client = try makeClient(server: signIn.server, store: store)
        let browser = signIn.browser()
        let caller = Task { try await client.signIn(using: browser) }
        await exchanging.wait()
        caller.cancel()
        answer.open()
        #expect(try await caller.value.subject == Fixture.subject)
        #expect(store.session?.refreshToken == "rt-1")
        #expect(signIn.server.requests(to: "/oauth/revoke").isEmpty)
    }

    @Test("while a 429 is waited out, sign-in refuses before the browser opens (§10.9 item 8)")
    func rateLimitedBeforeTheBrowser() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("slow_down", status: 429, headers: ["Retry-After": "30"]) }
        let clock = TestClock()
        let client = try makeClient(server: server, store: SpyStore(), clock: clock)
        // The code exchange is refused with a 429: the code is spent.
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 30)) {
            _ = try await client.signIn(using: StubBrowser.signsIn())
        }
        clock.advance(10)
        let browser = StubBrowser.signsIn()
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 20)) {
            _ = try await client.signIn(using: browser)
        }
        #expect(browser.openedURLs.isEmpty, "no password typed for a code that cannot be redeemed")
        #expect(server.requests(to: "/oauth/token").count == 1)

        clock.advance(21)
        let signIn = SignInServer(server: server)
        _ = try await client.signIn(using: signIn.browser())
    }

    @Test("a 429 from a refresh holds sign-in back too; a 429 without a usable Retry-After, for sixty seconds")
    func refreshRateLimitHoldsBackSignIn() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in HTTPResponse(status: 429) }
        let clock = TestClock()
        let client = try makeClient(server: server, store: SpyStore(.signedIn()), clock: clock)
        clock.advance(900)
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 60)) { _ = try await client.validAccessToken() }
        let browser = StubBrowser.signsIn()
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 60)) { _ = try await client.signIn(using: browser) }
        #expect(browser.openedURLs.isEmpty)
    }

    @Test("a callback without iss never reaches the token endpoint")
    func missingIssuerOnCallback() async throws {
        let signIn = SignInServer()
        let client = try makeClient(server: signIn.server, store: SpyStore())
        await #expect(throws: ProtelesAuthError.issuerMismatch(expected: Fixture.issuer, received: nil)) {
            _ = try await client.signIn(using: signIn.browser(.signsIn(issuer: nil)))
        }
        #expect(signIn.server.requests(to: "/oauth/token").isEmpty)
    }

    @Test("a callback with another state never reaches the token endpoint")
    func stateMismatch() async throws {
        let signIn = SignInServer()
        let client = try makeClient(server: signIn.server, store: SpyStore())
        await #expect(throws: ProtelesAuthError.stateMismatch) {
            _ = try await client.signIn(using: signIn.browser(.signsIn(state: "forged")))
        }
        #expect(signIn.server.requests(to: "/oauth/token").isEmpty)
    }

    @Test func anAuthorizationErrorIsTyped() async throws {
        let server = StubServer()
        let client = try makeClient(server: server, store: SpyStore())
        let browser = StubBrowser { url in
            let state = url.query["state"] ?? ""
            return URL(string: "\(Fixture.redirectURI)?error=access_denied&error_description=denied&state=\(state)&iss=https%3A%2F%2Fauth.example.test")!
        }
        await #expect(throws: ProtelesAuthError.authorization(error: "access_denied", description: "denied", errorURI: nil)) {
            _ = try await client.signIn(using: browser)
        }
        #expect(server.requests(to: "/oauth/token").isEmpty)
    }

    @Test("a second sign-in while one is showing the browser is refused, not run (a double tap)")
    func concurrentSignIn() async throws {
        let signIn = SignInServer()
        let client = try makeClient(server: signIn.server, store: SpyStore())
        let browser = GatedBrowser(then: signIn.browser())
        let first = Task { try await client.signIn(using: browser) }
        await browser.showing.wait()

        let second = StubBrowser.signsIn()
        await #expect(throws: ProtelesAuthError.alreadyInProgress) {
            _ = try await client.signIn(using: second)
        }
        #expect(second.openedURLs.isEmpty, "the second never opened a browser")

        browser.release.open()
        #expect(try await first.value.subject == Fixture.subject)
        #expect(signIn.server.requests(to: "/oauth/token").count == 1)
        // Once the first is over, signing in works again.
        _ = try await client.signIn(using: signIn.browser())
    }

    @Test("a lock that cannot be taken after the exchange fails the sign-in and revokes what it got (§10.9 item 7)")
    func signInWithoutTheLock() async throws {
        let signIn = SignInServer()
        let store = SpyStore()
        let unavailable = ProtelesAuthError.network("timed out after 60 s waiting for another process's refresh")
        let client = try makeClient(server: signIn.server, store: store, lock: UnavailableLock(unavailable))
        await #expect(throws: unavailable) { _ = try await client.signIn(using: signIn.browser()) }
        #expect(store.session == nil, "an unlocked write could land under another process's refresh")
        #expect(signIn.server.requests(to: "/oauth/revoke").map { $0.form["token"] } == ["rt-1"])
    }

    @Test("an end-session while a sign-in is showing raises already in progress, and signs nothing out (§10.9 item 8)")
    func endSessionWhileSigningIn() async throws {
        let signIn = SignInServer()
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: signIn.server, store: store)
        let browser = GatedBrowser(then: signIn.browser())
        let first = Task { try await client.signIn(using: browser) }
        await browser.showing.wait()

        let second = StubBrowser.cancels()
        await #expect(throws: ProtelesAuthError.alreadyInProgress) {
            _ = try await client.signOut(endSession: second)
        }
        #expect(second.openedURLs.isEmpty)
        #expect(signIn.server.requests(to: "/oauth/revoke").isEmpty, "the double tap did nothing")

        browser.release.open()
        _ = try await first.value
        #expect(store.session?.refreshToken == "rt-1")
    }
}

extension URL {
    fileprivate var query: [String: String] {
        Dictionary(queryItems(of: self).map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a })
    }
}

@Suite("A valid access token (§10.3)")
struct RefreshTests {
    /// A server whose refresh grant rotates `rt-N` to `rt-N+1` and mints an ID
    /// token bound to the new access token, as this server does.
    /// `serverTime` is the server's clock, which signs the ID token; the
    /// client's is the test's `TestClock`, which a test can move on its own.
    static func rotatingServer(
        delay: UInt64 = 0,
        subject: String = Fixture.subject,
        atHashFor: String? = nil,
        signer: TestSigner = .shared,
        serverTime: @escaping @Sendable () -> Date = { Fixture.t0 }
    ) -> StubServer {
        let server = StubServer()
        let counter = Counter()
        server.on("/oauth/token") { request in
            guard request.form["grant_type"] == "refresh_token" else { return .oauthError("unsupported_grant_type") }
            if delay > 0 { try await Task.sleep(nanoseconds: delay) }
            let n = counter.next() + 1
            let access = "at-\(n)"
            let idToken = signer.idToken(nonce: nil, accessToken: atHashFor ?? access, subject: subject, issuedAt: serverTime())
            return .tokens(access: access, refresh: "rt-\(n)", idToken: idToken)
        }
        return server
    }

    @Test("under half its life, the stored token is returned without a request")
    func fresh() async throws {
        let server = StubServer()
        let clock = TestClock()
        let client = try makeClient(server: server, store: SpyStore(.signedIn()), clock: clock)
        clock.advance(449)
        #expect(try await client.validAccessToken() == "at-1")
        #expect(server.requests.isEmpty)
    }

    @Test("past half its life: refresh, rotate, persist the new refresh token before returning")
    func rotation() async throws {
        let server = Self.rotatingServer()
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(451)

        let token = try await client.validAccessToken()

        #expect(token == "at-2")
        let refresh = try #require(server.requests(to: "/oauth/token").first)
        #expect(refresh.form == ["grant_type": "refresh_token", "refresh_token": "rt-1", "client_id": Fixture.clientId])

        // The first write persists the rotation alone — with the previous
        // access token, still good at the server; the last completes it. Both
        // happened before the token was handed out.
        #expect(store.writes.count == 2)
        #expect(store.writes.first?.refreshToken == "rt-2")
        #expect(store.writes.first?.accessToken == "at-1")
        #expect(store.writes.first?.accessTokenExpiresAt == Fixture.t0.addingTimeInterval(900))
        #expect(store.writes.last?.refreshToken == "rt-2")
        #expect(store.writes.last?.accessToken == "at-2")
        #expect(store.writes.last?.accessTokenReceivedAt == clock.now)
        #expect(store.writes.last?.accessTokenExpiresAt == clock.now.addingTimeInterval(900))
        // The refresh-minted ID token (no nonce, at_hash of at-2) verified and
        // replaced the claims; the refresh token never went back to rt-1.
        #expect(store.session?.claims["email_verified"] == .bool(true))
        #expect(!store.writes.contains { $0.refreshToken == "rt-1" })
    }

    @Test(
        "if the new refresh token cannot be persisted, the storage error is raised — even while the stored token is good — and the session is not ended (§10.9 item 1)",
        arguments: [451.0, 900.0]
    )
    func persistBeforeUse(_ elapsed: TimeInterval) async throws {
        let server = Self.rotatingServer()
        let store = SpyStore(.signedIn())
        store.failWrites = [1]
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(elapsed)
        await #expect(throws: ProtelesAuthError.storage("simulated write failure")) {
            _ = try await client.validAccessToken()
        }
        #expect(store.session == StoredSession.signedIn(), "not cleared")
        #expect(server.requests(to: "/oauth/revoke").isEmpty)
    }

    @Test(
        "a 200 whose body then fails validation still has its new refresh token saved first (§10.9 item 5)",
        arguments: [451.0, 900.0]
    )
    func rotationSavedBeforeValidation(_ elapsed: TimeInterval) async throws {
        let server = StubServer()
        // A refresh token, and no expires_in: refused — after the rotation is kept.
        server.on("/oauth/token") { _ in
            .json(.object(["access_token": .string("at-2"), "token_type": .string("Bearer"), "refresh_token": .string("rt-2")]))
        }
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(elapsed)
        if elapsed < 900 {
            #expect(try await client.validAccessToken() == "at-1", "the stored token, still good")
        } else {
            do {
                _ = try await client.validAccessToken()
                Issue.record("expected the malformed response to be refused")
            } catch ProtelesAuthError.tokenEndpoint(error: "invalid_response", _, _) {
            }
        }
        #expect(store.session?.refreshToken == "rt-2", "the family's only live credential is not dropped")
        #expect(store.session?.accessToken == "at-1")
    }

    /// The three ways a refresh-minted ID token fails a trust rule the stub
    /// server can produce.
    enum Untrusted: String, CaseIterable, Sendable {
        case atHash, unknownKey, anotherSubject

        var reason: IDTokenRejection {
            switch self {
            case .atHash: .atHash
            case .unknownKey: .noUsableKey
            case .anotherSubject: .subjectChanged
            }
        }

        func server(serverTime: @escaping @Sendable () -> Date) -> StubServer {
            switch self {
            case .atHash: RefreshTests.rotatingServer(atHashFor: "some-other-access-token", serverTime: serverTime)
            // Signed by a key the published set does not hold, fetched fine.
            case .unknownKey: RefreshTests.rotatingServer(signer: .rotated, serverTime: serverTime)
            case .anotherSubject: RefreshTests.rotatingServer(subject: "user-2", serverTime: serverTime)
            }
        }
    }

    @Test(
        "a refresh-minted ID token that fails a trust rule ends the session at once — even while the stored token is good — and its family is revoked (§10.9 item 1)",
        arguments: Untrusted.allCases, [451.0, 900.0]
    )
    func untrustedRefreshedIDToken(_ untrusted: Untrusted, _ elapsed: TimeInterval) async throws {
        let clock = TestClock()
        let server = untrusted.server(serverTime: clock.function)
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(elapsed)
        await #expect(throws: ProtelesAuthError.idTokenRejected(untrusted.reason)) {
            _ = try await client.validAccessToken()
        }
        #expect(store.session == nil, "cleared, not softened into the stored token")
        #expect(server.requests(to: "/oauth/revoke").map { $0.form["token"] } == ["rt-2"], "the rotated family is ended")
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(server.requests(to: "/oauth/token").count == 1)
    }

    @Test("an early refresh whose ID token names a key the set cannot supply yet: the new tokens are kept with the previous claims")
    func keyRotationDuringAnEarlyRefresh() async throws {
        // The tenant rotated its signing key; the key set cannot be fetched
        // for the moment. That says nothing against the tokens the token
        // endpoint just handed over, so they are kept (as the Android SDK
        // does), and the ID token is verified on the next refresh.
        let clock = TestClock()
        let server = Self.rotatingServer(signer: .rotated, serverTime: clock.function)
        server.on("/.well-known/jwks.json") { _ in throw URLError(.timedOut) }
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(451)

        #expect(try await client.validAccessToken() == "at-2")
        #expect(store.session?.refreshToken == "rt-2")
        #expect(store.session?.idToken == StoredSession.signedIn().idToken, "not adopted: it was not verified")
        #expect(store.session?.claims == StoredSession.signedIn().claims)
        #expect(try await client.validAccessToken() == "at-2")
        #expect(server.requests(to: "/oauth/token").count == 1, "not a rotation per call")

        // At at-2's half-life, with the new key published, the next refresh
        // verifies and adopts.
        let keys = TestSigner.jwks(.shared, .rotated)
        server.on("/.well-known/jwks.json") { _ in HTTPResponse(status: 200, body: keys) }
        clock.advance(451)
        #expect(try await client.validAccessToken() == "at-3")
        #expect(store.session?.refreshToken == "rt-3")
        #expect(store.session?.claims["email_verified"] == .bool(true), "the verified claims adopted")
    }

    @Test(
        "a device clock more than a minute off the server's is not grounds to refuse a refresh-minted ID token (§10.9 item 2)",
        arguments: [-3600.0, 1800.0]
    )
    func deviceClockMoved(_ offset: TimeInterval) async throws {
        // The server signs at its own time; the user moved the device's clock.
        let server = Self.rotatingServer(serverTime: { Fixture.t0 })
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(offset)

        for _ in 0..<5 { #expect(try await client.validAccessToken() == "at-2") }
        #expect(server.requests(to: "/oauth/token").count == 1, "one rotation, not one per call")
        #expect(store.session?.refreshToken == "rt-2")
        #expect(server.requests(to: "/oauth/revoke").isEmpty, "a wrong clock is not a sign-out")
        // Its times cannot be checked on this clock, so its claims are not
        // adopted — as the Android SDK does; the session goes on either way.
        #expect(store.session?.idToken == StoredSession.signedIn().idToken)
    }

    @Test("a refresh-minted ID token is verified without the clock, but by every other rule")
    func refreshSkipsOnlyTheClock() async throws {
        let signer = TestSigner.shared
        let token = signer.idToken(nonce: nil, accessToken: "at", issuedAt: Fixture.t0)
        let farFuture = Fixture.t0.addingTimeInterval(86_400)
        var expectations = IDTokenExpectations(
            issuer: Fixture.issuer, audience: Fixture.clientId, nonce: .skippedForRefreshGrant,
            accessToken: "at", now: farFuture, judgesClock: false
        )
        let keys = JSONWebKeySet(json: .object(["keys": .array([signer.jwk])]))
        _ = try await IDTokenVerifier.verify(token, expecting: expectations, keys: keys)
        expectations.judgesClock = true
        await #expect(throws: ProtelesAuthError.idTokenRejected(.expired)) {
            _ = try await IDTokenVerifier.verify(token, expecting: expectations, keys: keys)
        }
        expectations.judgesClock = false
        expectations.accessToken = "another"
        await #expect(throws: ProtelesAuthError.idTokenRejected(.atHash)) {
            _ = try await IDTokenVerifier.verify(token, expecting: expectations, keys: keys)
        }
        let noExp = signer.sign(["iss": .string(Fixture.issuer), "sub": .string("u"), "aud": .string(Fixture.clientId)])
        expectations.accessToken = nil
        await #expect(throws: ProtelesAuthError.idTokenRejected(.expirationMissing), "exp must still be there") {
            _ = try await IDTokenVerifier.verify(noExp, expecting: expectations, keys: keys)
        }
    }

    @Test("invalid_grant clears the session and raises sign-in required — once, never retried")
    func invalidGrant() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("invalid_grant", description: "refresh token reuse") }
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(451) // still valid, but invalid_grant is terminal regardless

        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(store.session == nil)
        #expect(try await client.currentUser() == nil)
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(server.requests(to: "/oauth/token").count == 1)
    }

    @Test("a refresh token already known to be dead is never presented again, even when the store cannot be cleared (§10.9 item 1)")
    func aDeadRefreshTokenIsNotPresentedTwice() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("invalid_grant") }
        let store = SpyStore(.signedIn())
        store.failDeletes = true
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(900)
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(store.session != nil, "the delete failed")
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(try await client.currentUser() == nil)
        #expect(server.requests(to: "/oauth/token").count == 1, "rt-1 was not presented again")
        store.failDeletes = false
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(store.session == nil, "cleared once the store lets it")
        #expect(server.requests(to: "/oauth/token").count == 1)
    }

    @Test("a session known dead reads as signed out, and is deleted only under the lock after a re-read — never by a read (§10.9 item 1, §10.6)")
    func aDeadSessionIsDeletedUnderTheLock() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("invalid_grant") }
        let spy = SpyStore(.signedIn())
        spy.failDeletes = true
        let held = Recorded(false)
        let store = WitnessStore(spy, held: held)
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock, lock: FlaggingLock(held))
        clock.advance(900)
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        spy.failDeletes = false

        // A read outside the lock, where another process's sign-in could land
        // between it and a delete.
        #expect(try await client.currentUser() == nil)
        #expect(spy.session != nil, "a read deletes nothing")
        #expect(store.deletes.isEmpty)

        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(spy.session == nil)
        #expect(store.deletes == [true], "deleted holding the lock")
        #expect(server.requests(to: "/oauth/token").count == 1)
    }

    @Test("a sign-in another process writes over a dead session is not deleted: the re-read under the lock finds it")
    func aSignInOverADeadSessionStands() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("invalid_grant") }
        let store = SpyStore(.signedIn())
        store.failDeletes = true
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(900)
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        store.failDeletes = false
        try store.write(StoredSession.signedIn(at: clock.now, accessToken: "at-new", refreshToken: "rt-new").encoded())
        #expect(try await client.validAccessToken() == "at-new")
        #expect(store.session?.refreshToken == "rt-new")
    }

    @Test("invalid_grant for a token another process already rotated does not delete that process's session")
    func invalidGrantAfterAnUnlockedRotation() async throws {
        let store = SpyStore(.signedIn())
        let server = StubServer()
        let clock = TestClock()
        server.on("/oauth/token") { _ in
            // An extension without the shared lock rotated rt-1 first.
            try store.write(StoredSession.signedIn(at: clock.now, accessToken: "at-from-extension", refreshToken: "rt-from-extension").encoded())
            return .oauthError("invalid_grant")
        }
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(900)
        #expect(try await client.validAccessToken() == "at-from-extension")
        #expect(store.session?.refreshToken == "rt-from-extension")
    }

    @Test("429 raises rate-limited with Retry-After, and no request is made before it")
    func rateLimited() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("slow_down", status: 429, headers: ["Retry-After": "30"]) }
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(900) // expired: there is no token to fall back on

        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 30)) { _ = try await client.validAccessToken() }
        #expect(store.session == StoredSession.signedIn(), "a 429 changes nothing stored")

        clock.advance(10)
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 20)) { _ = try await client.validAccessToken() }
        #expect(server.requests(to: "/oauth/token").count == 1, "no retry loop; Retry-After honoured")

        clock.advance(21)
        server.on("/oauth/token") { _ in .tokens(access: "at-2", refresh: "rt-2", idToken: nil) }
        #expect(try await client.validAccessToken() == "at-2")
        #expect(server.requests(to: "/oauth/token").count == 2)
    }

    @Test("a 429 without a usable Retry-After still backs off, for sixty seconds, while the token is valid and after")
    func rateLimitedWithoutRetryAfter() async throws {
        let server = StubServer()
        // An RFC 850 date: legal once, not one this SDK reads.
        server.on("/oauth/token") { _ in HTTPResponse(status: 429, headers: ["Retry-After": "Friday, 15-Jan-27 08:30:00 GMT"]) }
        let clock = TestClock()
        let client = try makeClient(server: server, store: SpyStore(.signedIn()), clock: clock)

        clock.advance(500) // past half its life, still valid
        for _ in 0..<5 { #expect(try await client.validAccessToken() == "at-1") }
        #expect(server.requests(to: "/oauth/token").count == 1, "one request, not one per API call")

        clock.advance(61)
        #expect(try await client.validAccessToken() == "at-1")
        #expect(server.requests(to: "/oauth/token").count == 2)

        clock.advance(400) // expired
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 60)) { _ = try await client.validAccessToken() }
        clock.advance(15)
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 45)) { _ = try await client.validAccessToken() }
        #expect(server.requests(to: "/oauth/token").count == 3)
    }

    @Test("a Retry-After past any sense is capped at an hour")
    func absurdRetryAfter() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in HTTPResponse(status: 429, headers: ["Retry-After": "99999999999999999999"]) }
        let clock = TestClock()
        let client = try makeClient(server: server, store: SpyStore(.signedIn()), clock: clock)
        clock.advance(900)
        do {
            _ = try await client.validAccessToken()
            Issue.record("expected rate limited")
        } catch let error as ProtelesAuthError {
            #expect(error == .rateLimited(retryAfter: 3600))
            #expect(error.localizedDescription.contains("3600"), "describing it does not trap")
        }
        clock.advance(3601)
        server.on("/oauth/token") { _ in .tokens(access: "at-2", refresh: "rt-2", idToken: nil) }
        #expect(try await client.validAccessToken() == "at-2", "refreshing again after the cap, not after 1e20 s")
    }

    @Test(
        "a failed refresh is not tried again before min(30 s, half the stored token's remaining life) (§10.9 item 3)",
        arguments: [
            (451.0, 30.0),  // 449 s left: 30 s
            (880.0, 10.0),  // 20 s left: 10 s
        ]
    )
    func failureBackoff(_ elapsed: TimeInterval, _ wait: TimeInterval) async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("invalid_client", status: 401) }
        let clock = TestClock()
        let client = try makeClient(server: server, store: SpyStore(.signedIn()), clock: clock)
        clock.advance(elapsed)
        #expect(try await client.validAccessToken() == "at-1")
        clock.advance(wait - 1)
        #expect(try await client.validAccessToken() == "at-1")
        #expect(server.requests(to: "/oauth/token").count == 1)
        clock.advance(1)
        #expect(try await client.validAccessToken() == "at-1")
        #expect(server.requests(to: "/oauth/token").count == 2)
    }

    @Test("once the stored token has expired there is no time left to wait out: a refusal is raised, and asked again next call")
    func refusalAfterExpiry() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("invalid_client", status: 401) }
        let clock = TestClock()
        let client = try makeClient(server: server, store: SpyStore(.signedIn()), clock: clock)
        clock.advance(900)
        let refusal = ProtelesAuthError.tokenEndpoint(error: "invalid_client", description: nil, status: 401)
        await #expect(throws: refusal) { _ = try await client.validAccessToken() }
        await #expect(throws: refusal) { _ = try await client.validAccessToken() }
        #expect(server.requests(to: "/oauth/token").count == 2)
    }

    @Test("the stored token is handed out to its last second, not a margin short of it (§10.3)")
    func fallbackUntilExpiry() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in throw URLError(.notConnectedToInternet) }
        let clock = TestClock()
        let client = try makeClient(server: server, store: SpyStore(.signedIn()), clock: clock)
        clock.advance(899)
        #expect(try await client.validAccessToken() == "at-1")
    }

    @Test("backoff lives in memory, per client: another client on the same store is not held back")
    func backoffIsPerClient() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("slow_down", status: 429, headers: ["Retry-After": "30"]) }
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let first = try makeClient(server: server, store: store, clock: clock)
        clock.advance(900)
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 30)) { _ = try await first.validAccessToken() }
        let second = try makeClient(server: server, store: store, clock: clock)
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 30)) { _ = try await second.validAccessToken() }
        #expect(server.requests(to: "/oauth/token").count == 2)
    }

    @Test("an outage is retried on the next call, so it recovers as soon as the server does")
    func outageIsNotBackedOff() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in HTTPResponse(status: 503, body: Data("<html>maintenance</html>".utf8)) }
        let clock = TestClock()
        let client = try makeClient(server: server, store: SpyStore(.signedIn()), clock: clock)
        clock.advance(900)
        do {
            _ = try await client.validAccessToken()
            Issue.record("expected a network error")
        } catch ProtelesAuthError.network {
        }
        server.on("/oauth/token") { _ in .tokens(access: "at-2", refresh: "rt-2", idToken: nil) }
        #expect(try await client.validAccessToken() == "at-2")
    }

    @Test("a failed early refresh hands out the still-valid token")
    func earlyRefreshFailureFallsBack() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("slow_down", status: 429, headers: ["Retry-After": "60"]) }
        let clock = TestClock()
        let client = try makeClient(server: server, store: SpyStore(.signedIn()), clock: clock)
        clock.advance(500)
        #expect(try await client.validAccessToken() == "at-1")
        server.on("/oauth/token") { _ in throw URLError(.notConnectedToInternet) }
        clock.advance(100) // past Retry-After, still inside the token's life
        #expect(try await client.validAccessToken() == "at-1")
        #expect(server.requests(to: "/oauth/token").count == 2)
    }

    @Test func aNetworkFailureWithAnExpiredTokenIsANetworkError() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in throw URLError(.timedOut) }
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(900)
        do {
            _ = try await client.validAccessToken()
            Issue.record("expected a network error")
        } catch ProtelesAuthError.network {
        }
        #expect(store.session == StoredSession.signedIn(), "a network failure changes nothing stored")
    }

    @Test("concurrent callers share one refresh: the lock is taken once, not once per caller")
    func singleFlight() async throws {
        let server = Self.rotatingServer(delay: 150_000_000)
        let clock = TestClock()
        let lock = CountingLock()
        let client = try makeClient(server: server, store: SpyStore(.signedIn()), clock: clock, lock: lock)
        clock.advance(900)
        let tokens = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<20 { group.addTask { try await client.validAccessToken() } }
            return try await group.reduce(into: [String]()) { $0.append($1) }
        }
        #expect(tokens.count == 20)
        #expect(Set(tokens) == ["at-2"])
        #expect(server.requests(to: "/oauth/token").count == 1)
        // Without the in-process single flight the other nineteen would each
        // queue on the lock, re-read the store and return at-2 — one request
        // all the same. Only the lock count tells the two apart.
        #expect(lock.acquisitions == 1)
    }

    @Test("two clients sharing a store and a lock file: one refresh; the second re-reads after the lock")
    func crossProcessReRead() async throws {
        let server = Self.rotatingServer(delay: 150_000_000)
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let lockURL = temporaryLockURL()
        // Two actors with separate descriptors on one lock file are what two
        // processes look like to flock.
        let a = try makeClient(server: server, store: store, clock: clock, lock: FileRefreshLock(url: lockURL))
        let b = try makeClient(server: server, store: store, clock: clock, lock: FileRefreshLock(url: lockURL))
        #expect(a.lockScope == .crossProcess(lockFile: lockURL))
        clock.advance(900)
        async let first = a.validAccessToken()
        async let second = b.validAccessToken()
        let tokens = try await [first, second]
        #expect(tokens == ["at-2", "at-2"])
        #expect(server.requests(to: "/oauth/token").count == 1)
        #expect(store.session?.refreshToken == "rt-2")
    }

    @Test func aRotationlessServerKeepsTheRefreshToken() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .tokens(access: "at-2", refresh: nil, idToken: nil) }
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(900)
        #expect(try await client.validAccessToken() == "at-2")
        #expect(store.session?.refreshToken == "rt-1")
    }

    @Test func noSessionIsSignInRequired() async throws {
        let client = try makeClient(server: StubServer(), store: SpyStore())
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(try await client.currentUser() == nil)
    }

    @Test("an unreadable store is a storage error, never a sign-out")
    func unreadableStore() async throws {
        let store = SpyStore(.signedIn())
        store.failReads = true
        let client = try makeClient(server: StubServer(), store: store)
        await #expect(throws: ProtelesAuthError.self) { _ = try await client.validAccessToken() }
        do {
            _ = try await client.validAccessToken()
        } catch ProtelesAuthError.storage {
        }
        store.failReads = false
        #expect(store.session != nil, "nothing was cleared")
    }

    @Test("a record this SDK cannot decode is no session, and is left for sign-in to replace")
    func undecodableRecord() async throws {
        let store = InMemoryTokenStore(data: Data(#"{"version":99,"somethingElse":true}"#.utf8))
        let client = try makeClient(server: StubServer(), store: store)
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(try await client.currentUser() == nil)
        #expect(try store.read() != nil, "not deleted: it may belong to a newer SDK in another process")
    }

    @Test(
        "a clock set back within the skew is noise, not a reason to rotate; further back, the stored times are not trusted and it refreshes",
        arguments: [(-1.0, false), (-30.0, false), (-60.0, false), (-61.0, true), (-3600.0, true)]
    )
    func clockSetBack(_ offset: TimeInterval, _ refreshes: Bool) async throws {
        let server = Self.rotatingServer(serverTime: { Fixture.t0 })
        let clock = TestClock()
        let client = try makeClient(server: server, store: SpyStore(.signedIn()), clock: clock)
        clock.advance(offset)
        #expect(try await client.validAccessToken() == (refreshes ? "at-2" : "at-1"))
        #expect(server.requests(to: "/oauth/token").count == (refreshes ? 1 : 0))
    }

    @Test("the access token's lifetime starts before the refresh request is sent: time in flight counts against it")
    func lifetimeStartsBeforeTheRequest() async throws {
        let clock = TestClock()
        let server = StubServer()
        server.on("/oauth/token") { _ in
            clock.advance(20) // a slow network
            return .tokens(access: "at-2", refresh: "rt-2", idToken: nil)
        }
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(451)
        let sent = clock.now
        #expect(try await client.validAccessToken() == "at-2")
        #expect(store.session?.accessTokenReceivedAt == sent)
        #expect(store.session?.accessTokenExpiresAt == sent.addingTimeInterval(900))
    }

    // MARK: Writers outside the lock, and a lock that cannot be taken

    @Test("a sign-out made elsewhere during a refresh is not undone by the refresh's writes")
    func signOutElsewhereDuringARefresh() async throws {
        let store = SpyStore(.signedIn())
        let server = StubServer()
        server.on("/oauth/token") { _ in
            // Another process, without the shared lock, signs out while the
            // request is out; the server had already rotated.
            try store.delete()
            return .tokens(access: "at-2", refresh: "rt-2", idToken: TestSigner.shared.idToken(nonce: nil, accessToken: "at-2"))
        }
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(900)
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(store.session == nil)
        #expect(store.writes.isEmpty, "nothing written back over the sign-out")
        #expect(try await client.currentUser() == nil)
        #expect(server.requests(to: "/oauth/revoke").map { $0.form["token"] } == ["rt-2"],
                "the rotated family is held by nobody: revoked, not left alive for thirty days")
    }

    @Test("a sign-out made elsewhere while the refresh verifies its ID token is not undone either")
    func signOutElsewhereDuringVerification() async throws {
        let store = SpyStore(.signedIn())
        let server = Self.rotatingServer()
        let keys = TestSigner.jwks(.shared)
        server.on("/.well-known/jwks.json") { _ in
            try store.delete()
            return HTTPResponse(status: 200, body: keys)
        }
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(900)
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(store.session == nil)
        #expect(server.requests(to: "/oauth/revoke").map { $0.form["token"] } == ["rt-2"])
    }

    @Test("a sign-in made elsewhere during a refresh is not overwritten by it")
    func signInElsewhereDuringARefresh() async throws {
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let server = StubServer()
        server.on("/oauth/token") { _ in
            try store.write(StoredSession.signedIn(at: clock.now, accessToken: "at-new", refreshToken: "rt-new").encoded())
            return .tokens(access: "at-2", refresh: "rt-2", idToken: TestSigner.shared.idToken(nonce: nil, accessToken: "at-2"))
        }
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(900)
        #expect(try await client.validAccessToken() == "at-new")
        #expect(store.session?.refreshToken == "rt-new")
        #expect(server.requests(to: "/oauth/revoke").map { $0.form["token"] } == ["rt-2"], "the family this refresh rotated to is nobody's")
    }

    @Test("a refresh lock that cannot be taken hands out the still-valid token, and otherwise reports the lock's failure")
    func refreshWithoutTheLock() async throws {
        let server = Self.rotatingServer()
        let clock = TestClock()
        let unavailable = ProtelesAuthError.network("timed out after 60 s waiting for another process's refresh")
        let client = try makeClient(server: server, store: SpyStore(.signedIn()), clock: clock, lock: UnavailableLock(unavailable))
        clock.advance(500)
        #expect(try await client.validAccessToken() == "at-1")
        clock.advance(400)
        await #expect(throws: unavailable) { _ = try await client.validAccessToken() }
        #expect(server.requests(to: "/oauth/token").isEmpty)
    }

    @Test("another process holding the lock file past the timeout: the still-valid token, not an error")
    func lockFileHeldElsewhere() async throws {
        let url = temporaryLockURL()
        let other = HeldLockFile(url)
        defer { other.release() }
        let server = Self.rotatingServer()
        let clock = TestClock()
        let client = try makeClient(server: server, store: SpyStore(.signedIn()), clock: clock, lock: FileRefreshLock(url: url, timeout: 0.2))
        clock.advance(500)
        #expect(try await client.validAccessToken() == "at-1")
        #expect(server.requests(to: "/oauth/token").isEmpty)
    }

    @Test("when the system is about to suspend the app, the refresh is cancelled and the App Group lock released (0xdead10cc)")
    func backgroundExpiryReleasesTheLock() async throws {
        let requestSent = Gate()
        let server = StubServer()
        server.on("/oauth/token") { _ in
            requestSent.open()
            // A network that drops packets: only cancellation ends this.
            try await Task.sleep(nanoseconds: 60_000_000_000)
            return .tokens(access: "at-2", refresh: "rt-2", idToken: nil)
        }
        let url = temporaryLockURL()
        let activity = ManualActivity()
        let store = SpyStore(.signedIn())
        let clock = TestClock()
        let client = try makeClient(
            server: server, store: store, clock: clock,
            lock: FileRefreshLock(url: url), backgroundActivity: activity
        )
        clock.advance(500)

        let call = Task { try await client.validAccessToken() }
        await requestSent.wait()
        await #expect(throws: ProtelesAuthError.self, "the refresh holds the lock file") {
            try await FileRefreshLock(url: url, timeout: 0.1).withLock {}
        }
        #expect(activity.counts.begun == 1 && activity.counts.ended == 0)

        activity.expire()
        #expect(try await call.value == "at-1", "cancelled; the still-valid token handed out")
        #expect(activity.counts.ended == 1, "the background time was given back")
        #expect(try await FileRefreshLock(url: url, timeout: 1).withLock { true }, "released before suspension")
        #expect(store.session?.refreshToken == "rt-1")
    }
}

@Suite("Sign out (§10.4)")
struct SignOutTests {
    @Test func revokesTheRefreshTokenAndClears() async throws {
        let server = StubServer()
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: server, store: store)
        let result = try await client.signOut()
        #expect(result == SignOutResult(revocation: .revoked, endSession: .notRequested))
        let revoke = try #require(server.requests(to: "/oauth/revoke").first)
        #expect(revoke.form == ["token": "rt-1", "token_type_hint": "refresh_token", "client_id": Fixture.clientId])
        #expect(store.session == nil)
        #expect(try await client.currentUser() == nil)
    }

    @Test("clears even when revocation fails, and says so: an outage as .network", arguments: [500, 503])
    func revocationOutage(_ status: Int) async throws {
        let server = StubServer()
        server.on("/oauth/revoke") { _ in .oauthError("server_error", status: status) }
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: server, store: store)
        let result = try await client.signOut()
        guard case .failed(.network) = result.revocation else {
            Issue.record("expected a network failure, got \(result.revocation)")
            return
        }
        #expect(store.session == nil)
    }

    @Test("clears even when revocation is refused, and says so")
    func revocationRefused() async throws {
        let server = StubServer()
        server.on("/oauth/revoke") { _ in .oauthError("invalid_client", status: 401) }
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: server, store: store)
        let result = try await client.signOut()
        #expect(result.revocation == .failed(.tokenEndpoint(error: "invalid_client", description: nil, status: 401)))
        #expect(store.session == nil)
    }

    @Test("the session is gone from the device before the revocation request is sent")
    func clearsBeforeTheNetwork() async throws {
        let server = StubServer()
        let store = SpyStore(.signedIn())
        let storedDuringRevocation = Recorded<Bool?>(nil)
        server.on("/oauth/revoke") { _ in
            storedDuringRevocation.value = store.session != nil
            return HTTPResponse(status: 200)
        }
        let client = try makeClient(server: server, store: store)
        #expect(try await client.signOut().revocation == .revoked)
        #expect(storedDuringRevocation.value == false)
    }

    @Test("a refresh lock that cannot be taken does not stop a sign-out")
    func lockUnavailable() async throws {
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: StubServer(), store: store, lock: UnavailableLock())
        let result = try await client.signOut()
        #expect(result.revocation == .revoked)
        #expect(store.session == nil)
    }

    @Test("another process holding the lock file past the timeout does not stop a sign-out")
    func lockFileHeldElsewhere() async throws {
        let url = temporaryLockURL()
        let other = HeldLockFile(url)
        defer { other.release() }
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: StubServer(), store: store, lock: FileRefreshLock(url: url, timeout: 0.2))
        let result = try await client.signOut()
        #expect(result.revocation == .revoked)
        #expect(store.session == nil)
    }

    @Test("a sign-out whose caller is cancelled while it waits for the lock carries on: it clears under the lock, then revokes (§10.9 item 6)")
    func cancelledWhileWaiting() async throws {
        let url = temporaryLockURL()
        let other = HeldLockFile(url)
        defer { other.release() }
        let server = StubServer()
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: server, store: store, lock: FileRefreshLock(url: url, timeout: 30))
        let signOut = Task { try await client.signOut() }
        try await Task.sleep(nanoseconds: 100_000_000)
        signOut.cancel()
        try await Task.sleep(nanoseconds: 100_000_000)
        #expect(store.session != nil, "still waiting for the other process's refresh, not cut short by the cancellation")
        other.release()
        #expect(try await signOut.value.revocation == .revoked)
        #expect(store.session == nil)
    }

    @Test("the revocation is not the caller's to cancel either (§10.9 item 6)")
    func cancelledWhileRevoking() async throws {
        let server = StubServer()
        let revoking = Gate()
        let answer = Gate()
        server.on("/oauth/revoke") { _ in
            revoking.open()
            await answer.wait()
            try Task.checkCancellation()
            return HTTPResponse(status: 200)
        }
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: server, store: store)
        let signOut = Task { try await client.signOut() }
        await revoking.wait()
        signOut.cancel()
        answer.open()
        #expect(try await signOut.value.revocation == .revoked)
        #expect(store.session == nil)
    }

    @Test("a record that cannot be read is still deleted, and its refresh token reported as not revoked")
    func unreadableRecord() async throws {
        let server = StubServer()
        let store = SpyStore(.signedIn())
        store.failReads = true
        let client = try makeClient(server: server, store: store)
        let result = try await client.signOut()
        guard case .failed(.storage) = result.revocation else {
            Issue.record("expected a storage failure, got \(result.revocation)")
            return
        }
        store.failReads = false
        #expect(store.session == nil)
        #expect(server.requests(to: "/oauth/revoke").isEmpty)
    }

    @Test("a record this SDK cannot decode is deleted, and reported as not revoked")
    func undecodableRecord() async throws {
        let store = InMemoryTokenStore(data: Data(#"{"version":99,"somethingElse":true}"#.utf8))
        let client = try makeClient(server: StubServer(), store: store)
        let result = try await client.signOut()
        guard case .failed(.storage) = result.revocation else {
            Issue.record("expected a storage failure, got \(result.revocation)")
            return
        }
        #expect(try store.read() == nil)
    }

    @Test("a record this SDK cannot decode but which names this issuer, this client and its refresh token has that token revoked")
    func undecodableRecordWithARefreshToken() async throws {
        let server = StubServer()
        let store = InMemoryTokenStore(data: Data(#"{"version":2,"issuer":"https://auth.example.test","clientId":"com.example.mobile","refreshToken":"rt-newer","layout":"newer"}"#.utf8))
        let client = try makeClient(server: server, store: store)
        #expect(try await client.signOut().revocation == .revoked)
        #expect(server.requests(to: "/oauth/revoke").first?.form["token"] == "rt-newer")
        #expect(try store.read() == nil)
    }

    @Test(
        "an undecodable record that does not name this issuer and client does not have its refresh token sent here",
        arguments: [
            #"{"version":2,"issuer":"https://other.example.test","clientId":"com.example.mobile","refreshToken":"rt-other"}"#,
            #"{"version":2,"issuer":"https://auth.example.test","clientId":"com.example.other","refreshToken":"rt-other"}"#,
            #"{"version":2,"refreshToken":"rt-other"}"#,
        ]
    )
    func undecodableRecordForAnotherConfiguration(_ record: String) async throws {
        let server = StubServer()
        let store = InMemoryTokenStore(data: Data(record.utf8))
        let client = try makeClient(server: server, store: store)
        guard case .failed(.storage) = try await client.signOut().revocation else {
            Issue.record("expected the token to be reported as not revoked")
            return
        }
        #expect(server.requests(to: "/oauth/revoke").isEmpty)
        #expect(try store.read() == nil)
    }

    @Test("a store that cannot be cleared: the storage error is raised, the token revoked all the same, and never presented again (§10.9 item 6)")
    func storeCannotBeCleared() async throws {
        let server = StubServer()
        let store = SpyStore(.signedIn())
        store.failDeletes = true
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        await #expect(throws: ProtelesAuthError.storage("simulated delete failure; the refresh token was revoked")) {
            _ = try await client.signOut()
        }
        #expect(server.requests(to: "/oauth/revoke").map { $0.form["token"] } == ["rt-1"],
                "the person asked to sign out; a revoked token in a stale store fails safe")
        #expect(store.session != nil)
        // The stale record reads as signed out here, and its dead refresh
        // token is not presented.
        #expect(try await client.currentUser() == nil)
        clock.advance(900)
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(server.requests(to: "/oauth/token").isEmpty)
    }

    @Test("a store that cannot be cleared and a revocation that fails: the storage error says both (§10.9 item 6)")
    func storeCannotBeClearedNorTokenRevoked() async throws {
        let server = StubServer()
        server.on("/oauth/revoke") { _ in HTTPResponse(status: 503) }
        let store = SpyStore(.signedIn())
        store.failDeletes = true
        let client = try makeClient(server: server, store: store)
        do {
            _ = try await client.signOut()
            Issue.record("expected a storage error")
        } catch ProtelesAuthError.storage(let message) {
            #expect(message.hasPrefix("simulated delete failure; revoking the refresh token failed too: "))
            #expect(message.contains("HTTP 503"), "\(message)")
        }
    }

    @Test("a refresh token already known dead is not presented at sign-out either")
    func signOutAfterADeadToken() async throws {
        let server = StubServer()
        server.on("/oauth/token") { _ in .oauthError("invalid_grant") }
        let store = SpyStore(.signedIn())
        store.failDeletes = true
        let clock = TestClock()
        let client = try makeClient(server: server, store: store, clock: clock)
        clock.advance(900)
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        store.failDeletes = false
        // Revoked all the same: the server burns the family for a spent
        // member, which ends one an offline revocation left alive (§10.9 item 6).
        server.on("/oauth/revoke") { _ in HTTPResponse(status: 200) }
        #expect(try await client.signOut().revocation == .revoked)
        #expect(server.requests(to: "/oauth/revoke").map { $0.form["token"] } == ["rt-1"])
        #expect(store.session == nil)
    }

    @Test("clears even when the server cannot be reached")
    func offline() async throws {
        let server = StubServer()
        server.on("/.well-known/openid-configuration") { _ in throw URLError(.notConnectedToInternet) }
        let store = SpyStore(.signedIn())
        let client = try makeClient(server: server, store: store)
        let result = try await client.signOut()
        guard case .failed(.network) = result.revocation else {
            Issue.record("expected a network failure, got \(result.revocation)")
            return
        }
        #expect(store.session == nil)
    }

    @Test func signedOutAlreadyIsNotAnError() async throws {
        let server = StubServer()
        let client = try makeClient(server: server, store: SpyStore())
        #expect(try await client.signOut().revocation == .notAttempted)
        #expect(server.requests.isEmpty)
    }

    @Test("ending the browser session too: id_token_hint, client_id, post_logout_redirect_uri, state")
    func endSession() async throws {
        let server = StubServer()
        let store = SpyStore(.signedIn())
        let client = try makeClient(
            server: server, store: store,
            configuration: Fixture.configuration(postLogoutRedirectURI: Fixture.postLogoutRedirectURI)
        )
        let browser = StubBrowser { url in
            let state = queryItems(of: url).first { $0.name == "state" }?.value ?? ""
            return URL(string: "\(Fixture.postLogoutRedirectURI)?state=\(state)")!
        }
        let result = try await client.signOut(endSession: browser)
        #expect(result == SignOutResult(revocation: .revoked, endSession: .completed))
        let url = try #require(browser.openedURLs.first)
        #expect(url.path == "/oauth/logout")
        let fields = Dictionary(queryItems(of: url).map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a })
        #expect(fields["id_token_hint"] == StoredSession.signedIn().idToken)
        #expect(fields["client_id"] == Fixture.clientId)
        #expect(fields["post_logout_redirect_uri"] == Fixture.postLogoutRedirectURI)
        #expect(fields["state"]?.count == 43)
        #expect(store.session == nil)
    }

    @Test func endSessionOutcomes() async throws {
        let configuration = try Fixture.configuration(postLogoutRedirectURI: Fixture.postLogoutRedirectURI)
        let forged = StubBrowser { _ in URL(string: "\(Fixture.postLogoutRedirectURI)?state=forged")! }
        var client = try makeClient(server: StubServer(), store: SpyStore(.signedIn()), configuration: configuration)
        #expect(try await client.signOut(endSession: forged).endSession == .failed(.stateMismatch))

        // The right state, returned somewhere else: not this end-session's
        // return. And one whose query does not decode.
        for returnTo in ["https://mobile.example.com/oauth/elsewhere", Fixture.redirectURI] {
            let elsewhere = StubBrowser { url in
                let state = queryItems(of: url).first { $0.name == "state" }?.value ?? ""
                return URL(string: "\(returnTo)?state=\(state)")!
            }
            client = try makeClient(server: StubServer(), store: SpyStore(.signedIn()), configuration: configuration)
            #expect(try await client.signOut(endSession: elsewhere).endSession == .failed(.stateMismatch), "\(returnTo)")
        }
        // A second state whose escape is well-formed but not UTF-8 (`URL`
        // itself re-escapes a malformed `%zz`, which would then read as a
        // plain second state).
        let malformed = StubBrowser { url in
            let state = queryItems(of: url).first { $0.name == "state" }?.value ?? ""
            let returned = URL(string: "\(Fixture.postLogoutRedirectURI)?state=\(state)&state=%FF")!
            precondition(returned.absoluteString.hasSuffix("&state=%FF"), "the URL kept the escape as written")
            return returned
        }
        client = try makeClient(server: StubServer(), store: SpyStore(.signedIn()), configuration: configuration)
        #expect(try await client.signOut(endSession: malformed).endSession == .failed(.stateMismatch))

        client = try makeClient(server: StubServer(), store: SpyStore(.signedIn()))
        #expect(try await client.signOut(endSession: StubBrowser.cancels()).endSession == .dismissed)
    }
}

/// A thread-safe counter for stub handlers.
final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func next() -> Int {
        lock.lock()
        defer { lock.unlock() }
        value += 1
        return value
    }
}
