package com.proteles.auth

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** docs/mobile-SDKs.md §10.2, end to end against a scripted server. */
class SignInTest {
    private val enc = PercentEncoding::encode

    @Test
    fun `sign-in runs discovery, the browser hop, the exchange and verification, and persists before returning`(): Unit = runBlocking {
        val h = ClientHarness()
        val browser = h.browser()
        val claims = h.client.signIn(browser)

        assertEquals("user-1", claims.subject)
        // The authorization URL (§10.2 step 3)
        val authorize = queryOf(browser.opened.single())
        assertTrue(browser.opened.single().startsWith(AUTHORIZE))
        assertFalse(authorize.containsKey("login_hint"))

        // The exchange (§10.2 step 5): a public client's form, and nothing else.
        val exchange = h.tokenRequests.single()
        assertEquals(
            mapOf(
                "grant_type" to listOf("authorization_code"),
                "code" to listOf("the-code"),
                "redirect_uri" to listOf(REDIRECT),
                "client_id" to listOf(CLIENT_ID),
                "code_verifier" to exchange.form()["code_verifier"]!!,
            ),
            exchange.form(),
        )
        val verifier = exchange.formValue("code_verifier")!!
        assertEquals(43, verifier.length)
        assertEquals(authorize["code_challenge"]!!.single(), Pkce.challenge(verifier), "the verifier answers the challenge")
        assertEquals("application/x-www-form-urlencoded", exchange.headers["Content-Type"])
        assertNull(exchange.headers["Authorization"], "a public client sends no credentials")
        assertEquals("POST", exchange.method)

        // Persisted before the caller saw it (§10.2 step 7).
        val stored = h.store.writes.single()
        assertEquals("at-1", stored.accessToken)
        assertEquals("rt-1", stored.refreshToken)
        assertEquals("user-1", stored.claims!!.subject)
        assertEquals(h.clock.epochSeconds() + 900, stored.expiresAt)
        assertEquals("user-1", h.client.currentClaims()!!.subject)
        assertEquals("at-1", h.client.validAccessToken())
        assertEquals(1, h.transport.requestsTo(DISCOVERY).size)
    }

    @Test
    fun `the user dismissing the browser is Cancelled, and nothing else happens`(): Unit = runBlocking {
        val h = ClientHarness()
        assertFailsWith<ProtelesException.Cancelled> {
            h.client.signIn(FakeBrowser { _, _ -> throw ProtelesException.Cancelled() })
        }
        assertTrue(h.tokenRequests.isEmpty())
        assertTrue(h.store.writes.isEmpty())
    }

    @Test
    fun `a callback with another state is refused before any code is exchanged`(): Unit = runBlocking {
        val h = ClientHarness()
        assertFailsWith<ProtelesException.StateMismatch> {
            h.client.signIn(h.browser { _ -> "$REDIRECT?code=stolen&state=attacker&iss=${enc(ISSUER)}" })
        }
        assertTrue(h.tokenRequests.isEmpty())
    }

    @Test
    fun `a callback without iss, or with another, is refused before any code is exchanged`(): Unit = runBlocking {
        val h = ClientHarness()
        assertFailsWith<ProtelesException.IssuerMismatch> { h.client.signIn(h.browser { s -> "$REDIRECT?code=c&state=$s" }) }
        assertFailsWith<ProtelesException.IssuerMismatch> {
            h.client.signIn(h.browser { s -> "$REDIRECT?code=c&state=$s&iss=${enc("https://evil.example")}" })
        }
        assertTrue(h.tokenRequests.isEmpty())
    }

    @Test
    fun `an error response is a typed authorization error`(): Unit = runBlocking {
        val h = ClientHarness()
        val e = assertFailsWith<ProtelesException.AuthorizationError> {
            h.client.signIn(h.browser { s -> "$REDIRECT?error=access_denied&error_description=denied&state=$s&iss=${enc(ISSUER)}" })
        }
        assertEquals("access_denied", e.error)
        assertEquals("denied", e.errorDescription)
        assertTrue(h.tokenRequests.isEmpty())
    }

    @Test
    fun `a refused exchange is a token endpoint error, not sign-in required`(): Unit = runBlocking {
        val h = ClientHarness()
        h.tokenEndpoint = { status(400, mapOf("error" to "invalid_grant", "error_description" to "code expired")) }
        val e = assertFailsWith<ProtelesException.TokenEndpointError> { h.client.signIn(h.browser()) }
        assertEquals("invalid_grant", e.error)
        assertEquals(400, e.httpStatus)
        assertTrue(h.store.writes.isEmpty())
    }

    @Test
    fun `an ID token for another login's nonce is refused, nothing is kept, and its refresh token is revoked`(): Unit = runBlocking {
        val h = ClientHarness()
        h.idTokenExtra = mapOf("nonce" to "somebody-elses")
        val e = assertFailsWith<ProtelesException.IdTokenRejected> { h.client.signIn(h.browser()) }
        assertEquals(IdTokenRejection.NONCE, e.reason)
        assertTrue(h.store.writes.isEmpty())
        assertNull(h.client.currentClaims())
        val revoke = h.transport.requestsTo(REVOKE).single()
        assertEquals("rt-1", revoke.formValue("token"))
    }

    @Test
    fun `an ID token whose at_hash describes another access token is refused (M3)`(): Unit = runBlocking {
        val h = ClientHarness()
        h.idTokenExtra = mapOf("at_hash" to IdTokenVerifier.atHash("another-access-token"))
        assertEquals(IdTokenRejection.AT_HASH, assertFailsWith<ProtelesException.IdTokenRejected> { h.client.signIn(h.browser()) }.reason)
        assertTrue(h.store.writes.isEmpty())
    }

    @Test
    fun `a token response without an ID token is refused`(): Unit = runBlocking {
        val h = ClientHarness()
        h.issueIdToken = false
        assertEquals(IdTokenRejection.MISSING, assertFailsWith<ProtelesException.IdTokenRejected> { h.client.signIn(h.browser()) }.reason)
    }

    @Test
    fun `an ID token for another audience is refused`(): Unit = runBlocking {
        val h = ClientHarness()
        h.idTokenExtra = mapOf("aud" to "another-client")
        assertEquals(IdTokenRejection.AUDIENCE, assertFailsWith<ProtelesException.IdTokenRejected> { h.client.signIn(h.browser()) }.reason)
    }

    @Test
    fun `a failed store write fails the sign-in, and the tokens it could not keep are revoked`(): Unit = runBlocking {
        val h = ClientHarness()
        h.store.failWrites = true
        assertFailsWith<ProtelesException.Storage> { h.client.signIn(h.browser()) }
        assertEquals("rt-1", h.transport.requestsTo(REVOKE).single().formValue("token"), "no family left alive for 30 days")
    }

    @Test
    fun `a sign-in cancelled after the browser returned still exchanges, verifies and saves`(): Unit = runBlocking {
        val h = ClientHarness()
        val inFlight = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        h.tokenEndpoint = { inFlight.complete(Unit); release.await(); h.mint(it) }
        val caller = launch { h.client.signIn(h.browser()) }
        inFlight.await()
        caller.cancel() // e.g. the Activity was recreated by a rotation while the browser was in front
        release.complete(Unit)
        caller.join()
        assertTrue(caller.isCancelled)
        assertEquals("rt-1", h.store.session!!.refreshToken, "the user who authenticated is signed in")
        assertEquals("user-1", h.client.currentClaims()!!.subject)
        assertTrue(h.transport.requestsTo(REVOKE).isEmpty())
    }

    @Test
    fun `a sign-in cancelled while another process holds the lock still saves`(): Unit = runBlocking {
        val lock = HeldLock()
        val h = ClientHarness(lock = lock)
        lock.held = true
        val caller = launch { h.client.signIn(h.browser()) }
        lock.waiting.await()
        caller.cancel()
        lock.release.complete(Unit)
        caller.join()
        assertEquals("rt-1", h.store.session!!.refreshToken)
        assertTrue(h.transport.requestsTo(REVOKE).isEmpty())
    }

    @Test
    fun `while a 429's Retry-After runs, sign-in refuses before the browser opens`(): Unit = runBlocking {
        val h = ClientHarness()
        h.tokenEndpoint = { status(429, mapOf("error" to "rate_limited"), mapOf("Retry-After" to listOf("30"))) }
        assertEquals(30L, assertFailsWith<ProtelesException.RateLimited> { h.client.signIn(h.browser()) }.retryAfterSeconds)

        h.clock.advance(10)
        val browser = h.browser()
        assertEquals(20L, assertFailsWith<ProtelesException.RateLimited> { h.client.signIn(browser) }.retryAfterSeconds)
        assertTrue(browser.opened.isEmpty(), "no password typed for a code that cannot be redeemed")
        assertEquals(1, h.tokenRequests.size)

        h.clock.advance(20)
        h.tokenEndpoint = { h.mint(it) }
        assertEquals("user-1", h.client.signIn(h.browser()).subject)
    }

    @Test
    fun `a 429 without Retry-After holds sign-in for sixty seconds (10_9 items 3 and 8)`(): Unit = runBlocking {
        val h = ClientHarness()
        h.tokenEndpoint = { status(429) }
        assertEquals(60L, assertFailsWith<ProtelesException.RateLimited> { h.client.signIn(h.browser()) }.retryAfterSeconds)
        h.clock.advance(59)
        val browser = h.browser()
        assertEquals(1L, assertFailsWith<ProtelesException.RateLimited> { h.client.signIn(browser) }.retryAfterSeconds)
        assertTrue(browser.opened.isEmpty(), "checked before the browser opens")
        h.clock.advance(1)
        h.tokenEndpoint = { h.mint(it) }
        assertEquals("user-1", h.client.signIn(h.browser()).subject)
    }

    @Test
    fun `a 429 from the key set holds the next sign-in too, and revokes what the failed one got`(): Unit = runBlocking {
        val h = ClientHarness()
        h.transport.on("GET", JWKS) { status(429, headers = mapOf("Retry-After" to listOf("30"))) }
        assertEquals(30L, assertFailsWith<ProtelesException.RateLimited> { h.client.signIn(h.browser()) }.retryAfterSeconds)
        assertEquals("rt-1", h.transport.requestsTo(REVOKE).single().formValue("token"))
        val browser = h.browser()
        assertFailsWith<ProtelesException.RateLimited> { h.client.signIn(browser) }
        assertTrue(browser.opened.isEmpty())
        h.clock.advance(30)
        h.transport.on("GET", JWKS) { ok(jwksOf(h.key)) }
        assertEquals("user-1", h.client.signIn(h.browser()).subject)
    }

    /** A browser that stays open until [close] completes, then answers as [ClientHarness.browser] does. */
    private class HeldBrowser(h: ClientHarness) : BrowserHop {
        private val inner = h.browser()
        val showing = CompletableDeferred<Unit>()
        val close = CompletableDeferred<Unit>()

        override suspend fun open(url: String, returnUri: String?): String {
            showing.complete(Unit)
            close.await()
            return inner.open(url, returnUri)
        }
    }

    @Test
    fun `a second sign-in while one is showing is already in progress, and the first carries on (10_9 item 8)`(): Unit = runBlocking {
        val h = ClientHarness()
        val held = HeldBrowser(h)
        val first = async { h.client.signIn(held) }
        held.showing.await()

        val tapAgain = h.browser()
        assertFailsWith<ProtelesException.AlreadyInProgress> { h.client.signIn(tapAgain) }
        assertTrue(tapAgain.opened.isEmpty(), "the second call did nothing")
        // An end-session is refused too, before it does anything (as on iOS).
        assertFailsWith<ProtelesException.AlreadyInProgress> {
            h.client.signOut(endSession = FakeBrowser { _, _ -> error("must not open") })
        }
        assertEquals(0, h.store.clears)
        assertTrue(h.transport.requestsTo(REVOKE).isEmpty())

        held.close.complete(Unit)
        assertEquals("user-1", first.await().subject)
        assertEquals(1, h.tokenRequests.size)

        // Once it has finished — or failed — the next one may start.
        assertFailsWith<ProtelesException.Cancelled> { h.client.signIn(FakeBrowser { _, _ -> throw ProtelesException.Cancelled() }) }
        assertEquals("user-1", h.client.signIn(h.browser()).subject)
    }

    @Test
    fun `a sign-in while an end-session is showing is already in progress`(): Unit = runBlocking {
        val h = ClientHarness()
        h.client.signIn(h.browser())
        val showing = CompletableDeferred<Unit>()
        val close = CompletableDeferred<Unit>()
        val signOut = async {
            h.client.signOut(endSession = FakeBrowser { _, _ -> showing.complete(Unit); close.await(); throw ProtelesException.Cancelled() })
        }
        showing.await()
        assertFailsWith<ProtelesException.AlreadyInProgress> { h.client.signIn(h.browser()) }
        assertFailsWith<ProtelesException.AlreadyInProgress> { h.client.signOut(endSession = FakeBrowser { _, _ -> error("must not open") }) }
        close.complete(Unit)
        assertSame(SignOutResult.EndSession.Dismissed, signOut.await().endSession)
        assertEquals("user-1", h.client.signIn(h.browser()).subject)
    }

    @Test
    fun `a malformed token response after the exchange still revokes the refresh token it named (10_9 item 7)`(): Unit = runBlocking {
        val h = ClientHarness()
        h.tokenEndpoint = { ok(mapOf("access_token" to "x", "token_type" to "DPoP", "expires_in" to 900, "refresh_token" to "rt-orphan")) }
        assertEquals("invalid_response", assertFailsWith<ProtelesException.TokenEndpointError> { h.client.signIn(h.browser()) }.error)
        assertEquals("rt-orphan", h.transport.requestsTo(REVOKE).single().formValue("token"))
        assertTrue(h.store.writes.isEmpty())
    }

    @Test
    fun `a lock that cannot be taken after the exchange fails the sign-in and revokes what it got (10_9 item 7)`(): Unit = runBlocking {
        val lock = UnavailableLock()
        val h = ClientHarness(lock = lock)
        val e = assertFailsWith<ProtelesException.Network> { h.client.signIn(h.browser()) }
        assertTrue(e.message!!.contains("timed out"), e.message)
        assertEquals(1, lock.attempts)
        assertTrue(h.store.writes.isEmpty(), "not saved without the lock")
        assertEquals("rt-1", h.transport.requestsTo(REVOKE).single().formValue("token"))
    }

    @Test
    fun `the access token's lifetime starts before the code exchange is sent`(): Unit = runBlocking {
        val h = ClientHarness()
        val sentAt = h.clock.epochSeconds()
        h.tokenEndpoint = { request ->
            h.clock.advance(5) // a slow network: the answer arrives five seconds after the request left
            h.mint(request)
        }
        h.client.signIn(h.browser())
        val stored = h.store.session!!
        assertEquals(sentAt, stored.obtainedAt)
        assertEquals(sentAt + 900, stored.expiresAt, "never counted valid for longer than the server's 900 s")

        // So half-life falls 450 s after the request left, not after the answer.
        h.tokenEndpoint = { h.mint(it) }
        h.clock.set(sentAt + 450)
        assertEquals("at-2", h.client.validAccessToken())
    }

    @Test
    fun `expires_in must be positive - a fraction is not truncated to nothing, a huge one does not wrap`(): Unit = runBlocking {
        for (refused in listOf<Number>(0, 0.0, -1)) {
            val h = ClientHarness()
            h.expiresIn = refused
            val e = assertFailsWith<ProtelesException.TokenEndpointError>("$refused") { h.client.signIn(h.browser()) }
            assertEquals("invalid_response", e.error, "$refused")
            assertTrue(h.store.writes.isEmpty(), "$refused: nothing kept")
            assertEquals("rt-1", h.transport.requestsTo(REVOKE).single().formValue("token"), "$refused: what it got is revoked (10_9 item 7)")
        }
        for ((sent, lifetime) in listOf<Pair<Number, Long>>(0.9 to 1L, 1.5 to 1L, 60.5 to 60L, 900 to 900L)) {
            val h = ClientHarness()
            h.expiresIn = sent
            h.client.signIn(h.browser())
            val stored = h.store.session!!
            assertEquals(lifetime, stored.expiresAt - stored.obtainedAt, "expires_in $sent")
        }
        // A lifetime past the end of epoch seconds is held there, not wrapped
        // negative into a token that is expired on arrival and rotates on every call.
        val h = ClientHarness()
        h.expiresIn = 1e300
        h.client.signIn(h.browser())
        assertEquals(Long.MAX_VALUE, h.store.session!!.expiresAt)
        h.clock.advance(10L * 365 * 86_400)
        assertEquals("at-1", h.client.validAccessToken())
        assertEquals(1, h.tokenRequests.size, "no refresh")
    }

    @Test
    fun `a 5xx from the token endpoint is Network, not a refusal`(): Unit = runBlocking {
        val h = ClientHarness()
        h.tokenEndpoint = { status(503, mapOf("error" to "temporarily_unavailable")) }
        assertEquals(503, assertFailsWith<ProtelesException.Network> { h.client.signIn(h.browser()) }.httpStatus)
    }

    @Test
    fun `the claims outlive the ID token's own fifteen minutes (trap 7)`(): Unit = runBlocking {
        val h = ClientHarness()
        h.expiresIn = 3600 // the access token outlives the ID token
        h.client.signIn(h.browser())
        h.clock.advance(1200) // past the ID token's exp + skew, inside the access token's half-life
        assertEquals("user-1", h.client.currentClaims()!!.subject)
        assertEquals("at-1", h.client.validAccessToken())
    }

    @Test
    fun `a session stored for another issuer is not this configuration's`(): Unit = runBlocking {
        val h = ClientHarness()
        h.client.signIn(h.browser())
        val other = ClientHarness(store = h.store, configuration = ProtelesConfiguration("https://other.example.test", CLIENT_ID, REDIRECT))
        assertNull(other.client.currentClaims())
        assertFailsWith<ProtelesException.SignInRequired> { other.client.validAccessToken() }
        assertNotNull(h.client.currentClaims())
    }
}
