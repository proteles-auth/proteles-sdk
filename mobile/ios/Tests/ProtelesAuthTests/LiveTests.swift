import Foundation
import Testing
@testable import ProtelesAuth

// The SDK against a real Proteles server (docs/mobile-SDKs.md §10.8), not a
// stub: the real discovery document, login form, callback, token endpoint,
// key set, rotation and revocation. Only the person at the browser is stood in
// for (`LiveBrowser`), and the store is in memory — a test binary has no
// Keychain entitlement.
//
//   mobile/live/run-live.sh -- mobile/ios/scripts/swift-test.sh --filter Live
//
// Without PROTELES_LIVE_ISSUER every test here is skipped, so
// `scripts/swift-test.sh` and CI run exactly what they ran before. The suite
// is serialised: the server's login and token endpoints are rate-limited per
// network, and each test is a person's session from sign-in to sign-out.

/// One app on one device: its store, clock, lock, transport and browser. The
/// clock is a test clock started at the real time, so sign-in judges the real
/// server's ID token by the real clock, and a test can move it past the access
/// token's half-life to force a refresh without waiting seven and a half
/// minutes. The server keeps the real time throughout.
struct LiveDevice {
    let configuration: ProtelesConfiguration
    let clock = TestClock(Date())
    let store = SpyStore()
    let transport = RecordingTransport()
    let lockKey = "live-\(UUID().uuidString)"
    let browser: LiveBrowser

    init(withPostLogoutRedirect: Bool = false) throws {
        configuration = try Live.configuration(withPostLogoutRedirect: withPostLogoutRedirect)
        browser = try Live.browser()
    }

    /// A client over this device's store and lock — a second one is another
    /// part of the same app (§10.6).
    func client(transport: RecordingTransport? = nil) throws -> ProtelesClient {
        try ProtelesClient(
            configuration: configuration,
            transport: transport ?? self.transport,
            store: store,
            lock: InProcessRefreshLock(key: lockKey),
            now: clock.function,
            backgroundActivity: ManualActivity()
        )
    }

    var stored: StoredSession {
        get throws { try #require(store.session, "no session is stored") }
    }

    /// Moves the device's clock one second past the stored access token's
    /// half-life, where `validAccessToken` refreshes (§4 "refresh early").
    func passHalfLife() throws {
        let session = try stored
        let halfLife = session.accessTokenExpiresAt.timeIntervalSince(session.accessTokenReceivedAt) / 2
        let due = session.accessTokenReceivedAt.addingTimeInterval(halfLife + 1)
        clock.advance(max(0, due.timeIntervalSince(clock.now)))
    }
}

@Suite("Live: the SDK against a real server", .serialized, .enabled(if: Live.isConfigured, "set PROTELES_LIVE_ISSUER: run through mobile/live/run-live.sh"))
struct LiveTests {
    @Test("sign-in: discovery, PKCE, the callback's state and iss, the code exchange, and the ID token verified against the real key set with the real nonce and at_hash")
    func signIn() async throws {
        let server = try await LiveServer.discover()
        let device = try LiveDevice()
        let client = try device.client()

        let user = try await client.signIn(using: device.browser)

        // Discovery, once, and its issuer is the configured one byte for byte
        // (the sign-in would have failed otherwise).
        let discovery = device.transport.exchanges(to: "/.well-known/openid-configuration")
        #expect(discovery.map(\.response.status) == [200])

        // The authorization request: the contract's parameters, PKCE S256.
        let authorize = try #require(device.browser.openedURLs.first)
        let sent = Live.query(authorize)
        #expect(authorize.absoluteString.hasPrefix(server.issuer + "/oauth/authorize?"))
        #expect(Set(sent.keys) == [
            "response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
            "code_challenge", "code_challenge_method",
        ])
        #expect(sent["code_challenge_method"] == "S256")
        #expect(sent["code_challenge"]?.count == 43)
        #expect(device.browser.credentialsPosted == 1, "the real login form was filled in: \(device.browser.history)")

        // The callback the server sent: this sign-in's state, and the issuer.
        let callback = try #require(device.browser.callbacks.last)
        let returned = Live.query(callback)
        #expect(callback.absoluteString.hasPrefix(device.configuration.redirectURI + "?"))
        #expect(returned["state"] == sent["state"])
        #expect(returned["iss"] == server.issuer)
        let code = try #require(returned["code"])

        // The code exchange: that code, the same redirect URI, a verifier that
        // hashes to the challenge, and no secret.
        let exchange = try #require(device.transport.tokenRequests("authorization_code").first)
        #expect(exchange.response.status == 200)
        let form = exchange.request.form
        #expect(Set(form.keys) == ["grant_type", "code", "redirect_uri", "client_id", "code_verifier"])
        #expect(form["code"] == code)
        #expect(form["redirect_uri"] == sent["redirect_uri"])
        #expect(form["client_id"] == server.clientId)
        #expect(PKCE.challenge(for: form["code_verifier"] ?? "") == sent["code_challenge"])
        #expect(exchange.request.headers["Authorization"] == nil)

        // The ID token the SDK verified and kept carries this sign-in's nonce
        // and the at_hash of the access token it came with.
        let session = try device.stored
        let accessToken = try #require(session.accessToken)
        let idToken = try #require(session.idToken)
        let claims = Live.claims(of: idToken)
        #expect(claims["nonce"]?.stringValue == sent["nonce"])
        #expect(claims["at_hash"]?.stringValue == IDTokenVerifier.atHash(accessToken))
        #expect(claims["iss"]?.stringValue == server.issuer)
        #expect(claims["aud"]?.stringValue == server.clientId)
        #expect(session.refreshToken != nil, "a refresh token, from the grant and not from a scope (§2.3)")
        #expect(await client.keySetFetchCount() == 1, "the SDK fetched the real key set")

        // The same verification, run here against the published key set: it
        // accepts this token, and refuses it with another nonce, another
        // access token, or one byte of the payload changed — so the checks
        // above ran against the real key, nonce and at_hash, not past them.
        let keys = try await server.keySet()
        #expect(keys.keys.count >= 1)
        func verify(_ token: String, nonce: String?, accessToken: String) async throws {
            _ = try await IDTokenVerifier.verify(token, expecting: IDTokenExpectations(
                issuer: server.issuer, audience: server.clientId, nonce: .required(nonce ?? ""),
                accessToken: accessToken, now: device.clock.now), keys: keys)
        }
        try await verify(idToken, nonce: sent["nonce"], accessToken: accessToken)
        await #expect(throws: ProtelesAuthError.idTokenRejected(.nonce)) {
            try await verify(idToken, nonce: "another-sign-in", accessToken: accessToken)
        }
        await #expect(throws: ProtelesAuthError.idTokenRejected(.atHash)) {
            try await verify(idToken, nonce: sent["nonce"], accessToken: accessToken + "x")
        }
        var segments = idToken.split(separator: ".").map(String.init)
        var payload = try #require(Base64URL.decode(segments[1]))
        payload[payload.startIndex + 2] ^= 0x01
        segments[1] = Base64URL.encode(payload)
        await #expect(throws: ProtelesAuthError.idTokenRejected(.signature)) {
            try await verify(segments.joined(separator: "."), nonce: sent["nonce"], accessToken: accessToken)
        }

        // The seeded person, from the verified claims.
        #expect(!user.subject.isEmpty)
        #expect(user.issuer == server.issuer)
        #expect(user.preferredUsername == (try Live.username()))
        #expect(user.email == "\(try Live.username())@example.com")
        #expect(user.emailVerified == true)
        #expect(user.amr.contains("pwd"))
        let authTime = try #require(user.authTime)
        #expect(abs(authTime.timeIntervalSinceNow) < 300)
        #expect(try await client.currentUser() == user)

        // The real callback, tampered with, is refused — the same browser
        // session, so the server answers without asking for the password.
        let replayedState = TamperingBrowser(device.browser) { url in
            url.replacingQueryValue("state", with: "not-this-sign-in")
        }
        await #expect(throws: ProtelesAuthError.stateMismatch) {
            _ = try await client.signIn(using: replayedState)
        }
        let noIssuer = TamperingBrowser(device.browser) { url in url.replacingQueryValue("iss", with: nil) }
        await #expect(throws: ProtelesAuthError.issuerMismatch(expected: server.issuer, received: nil)) {
            _ = try await client.signIn(using: noIssuer)
        }
        #expect(device.browser.credentialsPosted == 1)
        #expect(device.transport.tokenRequests("authorization_code").count == 1, "a refused callback's code is never redeemed")
        #expect(try await client.currentUser() == user, "a refused sign-in leaves the session alone")

        #expect(try await client.signOut().revocation == .revoked)
    }

    @Test("validAccessToken returns a token the server accepts at userinfo, for the seeded person")
    func accessTokenIsAccepted() async throws {
        let server = try await LiveServer.discover()
        let device = try LiveDevice()
        let client = try device.client()
        let user = try await client.signIn(using: device.browser)

        let token = try await client.validAccessToken()
        #expect(token == (try device.stored).accessToken)
        #expect(device.transport.tokenRequests("refresh_token").isEmpty, "a fresh token is not refreshed")

        let userinfo = try await server.userinfo(token)
        #expect(userinfo.status == 200)
        #expect(userinfo.claims["sub"]?.stringValue == user.subject)
        #expect(userinfo.claims["preferred_username"]?.stringValue == (try Live.username()))
        // A positive control needs its negative: the endpoint does refuse.
        #expect(try await server.userinfo(token + "x").status == 401)

        #expect(try await client.signOut().revocation == .revoked)
    }

    @Test("a refresh at half-life rotates the refresh token, persisted before use; the server refuses the old one and accepts the new access token")
    func refreshRotates() async throws {
        let server = try await LiveServer.discover()
        let device = try LiveDevice()
        let client = try device.client()
        let user = try await client.signIn(using: device.browser)
        let first = try device.stored
        let firstRefresh = try #require(first.refreshToken)
        let firstAccess = try #require(first.accessToken)

        try device.passHalfLife()
        let refreshed = try await client.validAccessToken()

        let refreshes = device.transport.tokenRequests("refresh_token")
        #expect(refreshes.count == 1)
        #expect(refreshes.first?.response.status == 200)
        #expect(refreshes.first?.request.form["refresh_token"] == firstRefresh)
        #expect(refreshes.first?.request.form["client_id"] == server.clientId)
        #expect(refreshed != firstAccess)

        let second = try device.stored
        let secondRefresh = try #require(second.refreshToken)
        #expect(secondRefresh != firstRefresh, "rotated")
        #expect(second.accessToken == refreshed)
        // Persisted first (§10.9 item 5): the rotated refresh token was
        // written with the previous access token before anything else.
        #expect(device.store.writes.map(\.refreshToken) == [firstRefresh, secondRefresh, secondRefresh])
        #expect(device.store.writes.map(\.accessToken) == [firstAccess, firstAccess, refreshed])

        // The refresh-minted ID token was verified and adopted: same person,
        // no nonce, the new access token's at_hash, auth_time inherited.
        let idToken = try #require(second.idToken)
        #expect(idToken != first.idToken)
        let claims = Live.claims(of: idToken)
        #expect(claims["nonce"] == nil)
        #expect(claims["at_hash"]?.stringValue == IDTokenVerifier.atHash(refreshed))
        let current = try #require(try await client.currentUser())
        #expect(current.subject == user.subject)
        #expect(current.authTime == user.authTime)

        #expect(try await server.userinfo(refreshed).status == 200)
        #expect(try await client.validAccessToken() == refreshed, "not refreshed again before its own half-life")

        // The spent token is refused…
        let replay = try await server.presentRefreshToken(firstRefresh)
        #expect(replay.status == 400)
        #expect(replay.error == "invalid_grant")
        // …and, presented within 60 s of its rotation, leaves the family
        // alone (§2.3): the SDK's current token still rotates.
        try device.passHalfLife()
        let third = try await client.validAccessToken()
        #expect(third != refreshed)
        #expect(device.transport.tokenRequests("refresh_token").map(\.response.status) == [200, 200])
        #expect(try await server.userinfo(third).status == 200)

        #expect(try await client.signOut().revocation == .revoked)
    }

    @Test("sign-out revokes at the server: the refresh token is then refused with invalid_grant, and validAccessToken raises sign-in required")
    func signOutRevokes() async throws {
        let server = try await LiveServer.discover()
        let device = try LiveDevice()
        let client = try device.client()
        _ = try await client.signIn(using: device.browser)
        let refreshToken = try #require(try device.stored.refreshToken)

        let result = try await client.signOut()
        #expect(result.revocation == .revoked)
        #expect(result.endSession == .notRequested)
        #expect(device.store.session == nil)

        let revocation = device.transport.exchanges(to: "/oauth/revoke")
        #expect(revocation.map(\.response.status) == [200])
        #expect(revocation.first?.request.form["token"] == refreshToken)
        #expect(revocation.first?.request.form["token_type_hint"] == "refresh_token")
        #expect(revocation.first?.request.form["client_id"] == server.clientId)

        let presented = try await server.presentRefreshToken(refreshToken)
        #expect(presented.status == 400)
        #expect(presented.error == "invalid_grant")

        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(try await client.currentUser() == nil)
        // A client that starts now over the same store finds nobody.
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await device.client().validAccessToken() }
        #expect(device.transport.tokenRequests("refresh_token").isEmpty, "nothing was presented after sign-out")
    }

    @Test("a sign-in whose session cannot be stored revokes, at the server, the refresh token it was issued (§10.9 item 7)")
    func unstorableSignInRevokes() async throws {
        let server = try await LiveServer.discover()
        let device = try LiveDevice()
        device.store.failWrites = [1]
        let client = try device.client()

        await #expect(throws: ProtelesAuthError.storage("simulated write failure")) {
            _ = try await client.signIn(using: device.browser)
        }
        let exchange = try #require(device.transport.tokenRequests("authorization_code").first)
        #expect(exchange.response.status == 200)
        let issued = try #require(JSONValue.parseObject(exchange.response.body)?["refresh_token"]?.stringValue)
        let revocation = device.transport.exchanges(to: "/oauth/revoke")
        #expect(revocation.map(\.response.status) == [200])
        #expect(revocation.first?.request.form["token"] == issued)
        #expect(try await server.presentRefreshToken(issued).error == "invalid_grant", "no thirty-day family is left behind")
        #expect(device.store.session == nil)
    }

    @Test("a family revoked where the SDK cannot see it: the server's invalid_grant at the next refresh ends the session, and the token is not presented again (§10.9 item 1)")
    func revokedElsewhere() async throws {
        let server = try await LiveServer.discover()
        let device = try LiveDevice()
        let client = try device.client()
        _ = try await client.signIn(using: device.browser)
        let signedIn = try device.stored
        let refreshToken = try #require(signedIn.refreshToken)

        #expect(try await server.revoke(refreshToken) == 200)
        // Nothing to notice until a refresh is due.
        #expect(try await client.validAccessToken() == signedIn.accessToken)

        try device.passHalfLife()
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        let refused = device.transport.tokenRequests("refresh_token")
        #expect(refused.map(\.response.status) == [400])
        #expect(refused.first.flatMap { JSONValue.parseObject($0.response.body)?["error"]?.stringValue } == "invalid_grant")
        #expect(device.store.session == nil, "cleared at once")
        #expect(try await client.currentUser() == nil)

        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await client.validAccessToken() }
        #expect(device.transport.tokenRequests("refresh_token").count == 1, "invalid_grant is never retried")
        #expect(try await client.signOut().revocation == .notAttempted)
    }

    @Test("a second client over the same store sees the session, its refresh, and its sign-out")
    func secondClientSeesTheSession() async throws {
        let server = try await LiveServer.discover()
        let device = try LiveDevice()
        let app = try device.client()
        let user = try await app.signIn(using: device.browser)
        let signedIn = try device.stored

        let extensionTransport = RecordingTransport()
        let appExtension = try device.client(transport: extensionTransport)
        #expect(try await appExtension.currentUser() == user)
        #expect(try await appExtension.validAccessToken() == signedIn.accessToken)
        #expect(extensionTransport.exchanges(to: "/oauth/token").isEmpty)

        // The extension refreshes; the app picks up its rotation from the
        // store instead of presenting the spent token.
        try device.passHalfLife()
        let rotated = try await appExtension.validAccessToken()
        #expect(extensionTransport.tokenRequests("refresh_token").map(\.response.status) == [200])
        #expect(try await app.validAccessToken() == rotated)
        #expect(device.transport.tokenRequests("refresh_token").isEmpty, "the app did not refresh again")
        #expect(try await server.userinfo(rotated).status == 200)
        #expect(try device.stored.refreshToken != signedIn.refreshToken)

        // Both at once, at the next half-life: one rotation between them
        // (§10.6). A second would present the spent token, which this server
        // refuses — and each client would end up with a different answer.
        try device.passHalfLife()
        async let fromApp = app.validAccessToken()
        async let fromExtension = appExtension.validAccessToken()
        let (appToken, extensionToken) = try await (fromApp, fromExtension)
        #expect(appToken == extensionToken)
        let allRefreshes = device.transport.tokenRequests("refresh_token") + extensionTransport.tokenRequests("refresh_token")
        #expect(allRefreshes.map(\.response.status) == [200, 200], "one refresh each half-life, however many clients ask")
        #expect(try await server.userinfo(appToken).status == 200)
        let rotatedRefresh = try #require(try device.stored.refreshToken)

        // The app signs out; the extension sees it, and the family is dead.
        #expect(try await app.signOut().revocation == .revoked)
        #expect(device.transport.exchanges(to: "/oauth/revoke").first?.request.form["token"] == rotatedRefresh)
        #expect(try await appExtension.currentUser() == nil)
        await #expect(throws: ProtelesAuthError.signInRequired) { _ = try await appExtension.validAccessToken() }
        #expect(try await server.presentRefreshToken(rotatedRefresh).error == "invalid_grant")
    }

    @Test("the browser session: a second sign-in is silent until sign-out ends it at end_session_endpoint (§10.4, M5)")
    func endSession() async throws {
        let device = try LiveDevice(withPostLogoutRedirect: true)
        let client = try device.client()

        _ = try await client.signIn(using: device.browser)
        #expect(device.browser.credentialsPosted == 1)
        // Signing out without the browser leaves it signed in (trap 10)…
        #expect(try await client.signOut() == SignOutResult(revocation: .revoked, endSession: .notRequested))
        let again = try await client.signIn(using: device.browser)
        #expect(device.browser.credentialsPosted == 1, "the second sign-in rode the browser session")

        // …and with it, the server's confirmation is accepted and the browser
        // comes back to the post-logout redirect with our state.
        let result = try await client.signOut(endSession: device.browser)
        #expect(result == SignOutResult(revocation: .revoked, endSession: .completed))
        let opened = try #require(device.browser.openedURLs.last)
        let sent = Live.query(opened)
        #expect(opened.path == "/oauth/logout")
        #expect(sent["client_id"] == device.configuration.clientId)
        #expect(sent["post_logout_redirect_uri"] == device.configuration.postLogoutRedirectURI)
        #expect(Live.claims(of: sent["id_token_hint"] ?? "")["sub"]?.stringValue == again.subject)
        let back = try #require(device.browser.callbacks.last)
        #expect(back.absoluteString.hasPrefix((device.configuration.postLogoutRedirectURI ?? "") + "?"))
        #expect(Live.query(back)["state"] == sent["state"])

        _ = try await client.signIn(using: device.browser)
        #expect(device.browser.credentialsPosted == 2, "the browser session is over: the password was asked for again")
        #expect(try await client.signOut().revocation == .revoked)

        // Ending a browser session that is already over, with nothing stored
        // (so no id_token_hint): the server sends the browser straight back.
        let endedAgain = try await client.signOut(endSession: device.browser)
        #expect(endedAgain == SignOutResult(revocation: .notAttempted, endSession: .completed))
        #expect(Live.query(try #require(device.browser.openedURLs.last))["id_token_hint"] == nil)
    }
}

/// The live browser, with the callback it returns altered before the SDK sees it.
struct TamperingBrowser: AuthorizationBrowser {
    let inner: LiveBrowser
    let change: @Sendable (URL) -> URL

    init(_ inner: LiveBrowser, _ change: @escaping @Sendable (URL) -> URL) {
        self.inner = inner
        self.change = change
    }

    @MainActor
    func open(_ url: URL, redirectURI: URL) async throws -> URL {
        change(try await inner.open(url, redirectURI: redirectURI))
    }
}

extension URL {
    /// This URL with one query parameter's value replaced, or removed for `nil`.
    func replacingQueryValue(_ name: String, with value: String?) -> URL {
        var components = URLComponents(url: self, resolvingAgainstBaseURL: false)!
        let kept = FormEncoding.decode(components.percentEncodedQuery ?? "").filter { $0.name != name }
        let fields = kept.map { ($0.name, $0.value) } + (value.map { [(name, $0)] } ?? [])
        components.percentEncodedQuery = FormEncoding.encode(fields)
        return components.url!
    }
}
