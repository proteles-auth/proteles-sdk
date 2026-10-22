package com.proteles.auth

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.jupiter.api.Test
import java.io.IOException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** docs/mobile-SDKs.md §10.3 against a scripted token endpoint. */
class RefreshTest {
    private suspend fun signedIn(h: ClientHarness = ClientHarness()): ClientHarness {
        h.client.signIn(h.browser())
        h.store.writes.clear()
        h.transport.requests.clear()
        return h
    }

    @Test
    fun `before half-life the stored token is returned without a request`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(449) // half of 900 is 450
        assertEquals("at-1", h.client.validAccessToken())
        assertTrue(h.transport.requests.isEmpty())
    }

    @Test
    fun `past half-life it refreshes, rotates, and persists the new refresh token before returning`(): Unit = runBlocking {
        val h = signedIn()
        val idTokenBefore = h.store.session!!.idToken
        h.clock.advance(450)
        // The refresh-minted ID token carries no nonce; it is verified with the explicit null skip.
        assertEquals("at-2", h.client.validAccessToken())

        val request = h.tokenRequests.single()
        assertEquals(
            mapOf("grant_type" to listOf("refresh_token"), "refresh_token" to listOf("rt-1"), "client_id" to listOf(CLIENT_ID)),
            request.form(),
        )
        // First write: the rotated refresh token, with the old access token — the
        // only live credential is on disk before anything else can fail.
        assertEquals(2, h.store.writes.size)
        assertEquals("rt-2", h.store.writes[0].refreshToken)
        assertEquals("at-1", h.store.writes[0].accessToken)
        assertEquals("rt-2", h.store.writes[1].refreshToken)
        assertEquals("at-2", h.store.writes[1].accessToken)
        assertEquals("rt-2", h.store.session!!.refreshToken)
        assertEquals(h.clock.epochSeconds() + 900, h.store.session!!.expiresAt)
        assertNotEquals(idTokenBefore, h.store.session!!.idToken, "the verified refresh-minted ID token is adopted")

        // Rotation: the next refresh presents the new token, never the spent one.
        h.clock.advance(450)
        assertEquals("at-3", h.client.validAccessToken())
        assertEquals("rt-2", h.tokenRequests.last().formValue("refresh_token"))
    }

    @Test
    fun `the new access token is never returned unless the rotation was persisted`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(450)
        h.store.failWrites = true
        // §10.9 item 1: raised although the stored token is still valid — and the session is not ended.
        assertFailsWith<ProtelesException.Storage> { h.client.validAccessToken() }
        assertEquals(1, h.tokenRequests.size)
        assertEquals(0, h.store.clears, "a store that cannot be written does not end the session")
        assertEquals("rt-1", h.store.session!!.refreshToken)
        assertTrue(h.transport.requestsTo(REVOKE).isEmpty())
    }

    @Test
    fun `a store that cannot be read is a storage error, never signed out`(): Unit = runBlocking {
        val h = signedIn()
        h.store.failReads = true
        assertFailsWith<ProtelesException.Storage> { h.client.validAccessToken() }
        assertFailsWith<ProtelesException.Storage> { h.client.currentClaims() }
        h.store.failReads = false
        assertEquals("at-1", h.client.validAccessToken(), "nothing was cleared")
    }

    @Test
    fun `a record that can never be read is no session, and is left for the next sign-in`(): Unit = runBlocking {
        val h = signedIn()
        h.store.unreadable = true
        assertFailsWith<ProtelesException.SignInRequired> { h.client.validAccessToken() }
        assertNull(h.client.currentClaims())
        assertEquals(0, h.store.clears)
        assertTrue(h.transport.requests.isEmpty())
        h.client.signIn(h.browser())
        assertEquals("user-1", h.client.currentClaims()!!.subject)
    }

    /** Serves a refresh whose ID token is signed by [signer], a key the client has not cached. */
    private fun ClientHarness.signRefreshWith(signer: SigningKey) {
        tokenEndpoint = { request ->
            val body = Json.parseObjectUtf8(mint(request).body)
            val members = LinkedHashMap(body.members)
            members["id_token"] = JsonString(signer.sign(idTokenClaims(serverNow(), accessToken = body.string("access_token"))))
            HttpResponse(200, emptyMap(), Json.write(JsonObject(members)).toByteArray())
        }
    }

    @Test
    fun `when the key set cannot be fetched, the refreshed tokens are kept with the previous claims and nothing rotates again`(): Unit = runBlocking {
        val h = signedIn()
        val idTokenBefore = h.store.session!!.idToken
        h.clock.advance(450)
        h.signRefreshWith(SigningKey("rotated-key")) // a key the cache does not hold: a refetch is needed
        h.transport.on("GET", JWKS) { throw IOException("offline") }

        assertEquals("at-2", h.client.validAccessToken(), "the new access token is returned, not dropped")
        val stored = h.store.session!!
        assertEquals("rt-2", stored.refreshToken)
        assertEquals("at-2", stored.accessToken)
        assertEquals(h.clock.epochSeconds(), stored.obtainedAt)
        assertEquals(idTokenBefore, stored.idToken, "an ID token that could not be verified is not adopted")
        assertEquals("user-1", h.client.currentClaims()!!.subject)

        // The next calls use the new token: no second rotation against the shared budget.
        h.clock.advance(60)
        assertEquals("at-2", h.client.validAccessToken())
        assertEquals(1, h.tokenRequests.size)
    }

    @Test
    fun `a key set with no usable key does not make every refresh rotate and fail`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(450)
        h.signRefreshWith(SigningKey("rotated-key"))
        h.transport.on("GET", JWKS) { ok(mapOf("keys" to emptyList<Any>())) }
        assertEquals("at-2", h.client.validAccessToken())
        h.clock.advance(450)
        assertEquals("at-3", h.client.validAccessToken())
        assertEquals(listOf("rt-1", "rt-2"), h.tokenRequests.map { it.formValue("refresh_token") })
        assertEquals("user-1", h.client.currentClaims()!!.subject)
    }

    @Test
    fun `a caller cancelled mid-refresh does not lose the rotation`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(450)
        val inFlight = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        h.tokenEndpoint = { inFlight.complete(Unit); release.await(); h.mint(it) }
        val caller = launch { h.client.validAccessToken() }
        inFlight.await()
        caller.cancel() // e.g. the screen that asked was closed
        release.complete(Unit)
        caller.join()
        assertTrue(caller.isCancelled)
        // The server rotated when it answered; the new refresh token was kept anyway.
        assertEquals("rt-2", h.store.session!!.refreshToken)
        assertEquals("at-2", h.client.validAccessToken())
        assertEquals(1, h.tokenRequests.size)
    }

    @Test
    fun `invalid_grant clears the session and raises sign-in required, once, with no retry`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(450)
        h.tokenEndpoint = { status(400, mapOf("error" to "invalid_grant")) }
        val e = assertFailsWith<ProtelesException.SignInRequired> { h.client.validAccessToken() }
        // Walk the chain: with coroutine debugging on (as under test), stack-trace
        // recovery may wrap the exception in a copy of itself.
        val refused = generateSequence(e.cause) { it.cause }.filterIsInstance<ProtelesException.TokenEndpointError>().first()
        assertEquals("invalid_grant", refused.error)
        assertEquals(1, h.tokenRequests.size, "never retried")
        assertNull(h.store.session)
        assertNull(h.client.currentClaims())
        assertFailsWith<ProtelesException.SignInRequired> { h.client.validAccessToken() }
        assertEquals(1, h.tokenRequests.size, "a cleared session makes no request")
    }

    @Test
    fun `invalid_grant is never presented twice, even when the store cannot be cleared`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(450)
        h.tokenEndpoint = { status(400, mapOf("error" to "invalid_grant")) }
        h.store.failClears = true
        val e = assertFailsWith<ProtelesException.SignInRequired> { h.client.validAccessToken() }
        assertTrue(
            generateSequence<Throwable>(e) { it.cause }.any { c -> c.suppressed.any { it is ProtelesException.Storage } },
            "the store failure is reported alongside, not instead",
        )
        assertNotNull(h.store.session, "the record is still on disk")
        assertFailsWith<ProtelesException.SignInRequired> { h.client.validAccessToken() }
        assertNull(h.client.currentClaims(), "a session holding a dead refresh token reads as signed out")
        assertEquals(1, h.tokenRequests.size, "the dead refresh token was not sent again")

        // §10.9 item 1: a refresh token the SDK knows is dead ends the session —
        // the store is cleared as soon as it can be, and sign-in required raised.
        h.store.failClears = false
        assertFailsWith<ProtelesException.SignInRequired> { h.client.validAccessToken() }
        assertNull(h.store.session, "cleared once the store allowed it")
        assertEquals(1, h.tokenRequests.size)

        // A new sign-in replaces it.
        h.tokenEndpoint = { h.mint(it) }
        h.client.signIn(h.browser())
        assertEquals("user-1", h.client.currentClaims()!!.subject)
    }

    @Test
    fun `past half-life a failed refresh returns the stored token - the failure surfaces once it has expired`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(450)
        h.tokenEndpoint = { status(503) }
        assertEquals("at-1", h.client.validAccessToken(), "a server outage at half-life is not the caller's problem")
        assertEquals(1, h.tokenRequests.size)
        assertEquals("rt-1", h.store.session!!.refreshToken)

        // Held off for a while: API calls during an outage are not token requests.
        h.clock.advance(ProtelesClient.REFRESH_RETRY_SECONDS - 1)
        assertEquals("at-1", h.client.validAccessToken())
        assertEquals(1, h.tokenRequests.size)
        h.clock.advance(1)
        h.transport.on("POST", TOKEN) { throw IOException("offline") }
        assertEquals("at-1", h.client.validAccessToken())
        assertEquals(2, h.tokenRequests.size)

        // Expired (obtained at +0, 900 s): now the failure is the caller's.
        h.clock.set(h.store.session!!.expiresAt)
        assertFailsWith<ProtelesException.Network> { h.client.validAccessToken() }
        h.transport.on("POST", TOKEN) { status(503) }
        assertEquals(503, assertFailsWith<ProtelesException.Network> { h.client.validAccessToken() }.httpStatus)
        h.transport.on("POST", TOKEN) { status(400, mapOf("error" to "invalid_scope")) }
        assertEquals("invalid_scope", assertFailsWith<ProtelesException.TokenEndpointError> { h.client.validAccessToken() }.error)
        assertEquals("rt-1", h.store.session!!.refreshToken, "only invalid_grant ends the session")

        h.transport.on("POST", TOKEN) { h.mint(it) }
        assertEquals("at-2", h.client.validAccessToken())
    }

    @Test
    fun `the hold-off never outlasts half of the stored token's remaining life`(): Unit = runBlocking {
        val h = ClientHarness()
        h.expiresIn = 40 // a SAML session deadline can make it this short (§2.3)
        signedIn(h)
        h.clock.advance(20)
        h.tokenEndpoint = { status(503) }
        assertEquals("at-1", h.client.validAccessToken())
        h.clock.advance(10) // 20 s were left; a 30 s hold-off would reach expiry
        h.tokenEndpoint = { h.mint(it) }
        assertEquals("at-2", h.client.validAccessToken())
    }

    @Test
    fun `a 429 at half-life keeps the stored token, and no request is sent until Retry-After passes`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(450)
        h.tokenEndpoint = { status(429, mapOf("error" to "rate_limited"), mapOf("Retry-After" to listOf("60"))) }
        assertEquals("at-1", h.client.validAccessToken())
        assertEquals(1, h.tokenRequests.size)

        h.clock.advance(59)
        assertEquals("at-1", h.client.validAccessToken())
        assertEquals(1, h.tokenRequests.size, "no request into a latched bucket")

        h.clock.advance(1)
        h.tokenEndpoint = { h.mint(it) }
        assertEquals("at-2", h.client.validAccessToken())
        assertEquals(2, h.tokenRequests.size)
    }

    @Test
    fun `a 429 once the token has expired raises Retry-After, and no request is sent until it passes`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(900)
        h.tokenEndpoint = { status(429, mapOf("error" to "rate_limited"), mapOf("Retry-After" to listOf("30"))) }
        val first = assertFailsWith<ProtelesException.RateLimited> { h.client.validAccessToken() }
        assertEquals(30L, first.retryAfterSeconds)
        assertNotNull(h.store.session)
        assertEquals(1, h.tokenRequests.size)

        h.clock.advance(10)
        val second = assertFailsWith<ProtelesException.RateLimited> { h.client.validAccessToken() }
        assertEquals(20L, second.retryAfterSeconds)
        assertEquals(1, h.tokenRequests.size, "no request into a latched bucket")

        h.clock.advance(20)
        h.tokenEndpoint = { h.mint(it) }
        assertEquals("at-2", h.client.validAccessToken())
        assertEquals(2, h.tokenRequests.size)
    }

    @Test
    fun `Retry-After as seconds or an HTTP-date, capped at an hour (10_9 item 3)`() {
        val now = 1_800_000_000L // 2027-01-15T08:00:00Z
        assertEquals(90L, parseRetryAfter("Fri, 15 Jan 2027 08:01:30 GMT", now))
        assertEquals(0L, parseRetryAfter("Fri, 15 Jan 2027 07:00:00 GMT", now))
        assertEquals(5L, parseRetryAfter(" 5 ", now))
        assertEquals(3600L, parseRetryAfter("3600", now))
        assertEquals(3600L, parseRetryAfter("3601", now))
        assertEquals(3600L, parseRetryAfter("99999999999999999999999", now))
        assertEquals(3600L, parseRetryAfter("Sat, 16 Jan 2027 08:00:00 GMT", now), "a day ahead is read as an hour")
        assertNull(parseRetryAfter("soon", now))
        assertNull(parseRetryAfter("-5", now))
        assertNull(parseRetryAfter(null, now))
    }

    @Test
    fun `a 429 without a usable Retry-After backs off sixty seconds (10_9 item 3)`(): Unit = runBlocking {
        for (retryAfter in listOf(null, "soon")) {
            val h = signedIn()
            h.clock.advance(450)
            val headers = retryAfter?.let { mapOf("Retry-After" to listOf(it)) } ?: emptyMap()
            h.tokenEndpoint = { status(429, mapOf("error" to "rate_limited"), headers) }
            assertEquals("at-1", h.client.validAccessToken(), "at half-life the stored token is still good")
            h.clock.advance(59)
            assertEquals("at-1", h.client.validAccessToken())
            assertEquals(1, h.tokenRequests.size, "$retryAfter: nothing sent inside the sixty seconds")

            // Past expiry, inside a fresh 60 s wait: raised, with the wait the SDK is observing.
            h.clock.advance(1)
            h.clock.set(h.store.session!!.expiresAt)
            val limited = assertFailsWith<ProtelesException.RateLimited> { h.client.validAccessToken() }
            assertEquals(60L, limited.retryAfterSeconds)
            assertEquals(2, h.tokenRequests.size)
            h.clock.advance(59)
            assertEquals(1L, assertFailsWith<ProtelesException.RateLimited> { h.client.validAccessToken() }.retryAfterSeconds)
            assertEquals(2, h.tokenRequests.size)
            h.clock.advance(1)
            h.tokenEndpoint = { h.mint(it) }
            assertEquals("at-2", h.client.validAccessToken())
        }
    }

    @Test
    fun `a Retry-After beyond an hour is held for an hour`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(900)
        h.tokenEndpoint = { status(429, headers = mapOf("Retry-After" to listOf("86400"))) }
        assertEquals(3600L, assertFailsWith<ProtelesException.RateLimited> { h.client.validAccessToken() }.retryAfterSeconds)
        h.clock.advance(3599)
        assertFailsWith<ProtelesException.RateLimited> { h.client.validAccessToken() }
        assertEquals(1, h.tokenRequests.size)
        h.clock.advance(1)
        h.tokenEndpoint = { h.mint(it) }
        assertEquals("at-2", h.client.validAccessToken())
    }

    @Test
    fun `a 429 from discovery holds the refresh too, and nothing is sent before it passes`(): Unit = runBlocking {
        val h = signedIn()
        // Another process of the app, whose client has not fetched discovery yet.
        val cold = ClientHarness(clock = h.clock, store = h.store)
        cold.transport.on("GET", DISCOVERY) { status(429, headers = mapOf("Retry-After" to listOf("120"))) }
        h.clock.advance(900)
        assertEquals(120L, assertFailsWith<ProtelesException.RateLimited> { cold.client.validAccessToken() }.retryAfterSeconds)
        h.clock.advance(60)
        assertEquals(60L, assertFailsWith<ProtelesException.RateLimited> { cold.client.validAccessToken() }.retryAfterSeconds)
        assertEquals(1, cold.transport.requestsTo(DISCOVERY).size, "no request of any kind inside the wait")
        assertTrue(cold.tokenRequests.isEmpty())
    }

    @Test
    fun `concurrent callers share one refresh (single-flight)`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(450)
        val gate = CompletableDeferred<Unit>()
        h.tokenEndpoint = { gate.await(); h.mint(it) }
        val callers = (1..20).map { async { h.client.validAccessToken() } }
        repeat(10) { yield() }
        gate.complete(Unit)
        assertEquals(List(20) { "at-2" }, callers.awaitAll())
        assertEquals(1, h.tokenRequests.size)
    }

    @Test
    fun `concurrent callers share one refresh (many threads)`(): Unit = runBlocking(Dispatchers.Default) {
        val h = signedIn()
        h.clock.advance(450)
        h.tokenEndpoint = { delay(200); h.mint(it) }
        val tokens = (1..50).map { async { h.client.validAccessToken() } }.awaitAll()
        assertEquals(setOf("at-2"), tokens.toSet())
        assertEquals(1, h.tokenRequests.size)
    }

    @Test
    fun `two clients in one process over one record, with one lock key, refresh once`(): Unit = runBlocking(Dispatchers.Default) {
        val tokens = twoClientsRefreshTogether(CrossProcessLock.inProcessOnly("one-record"), CrossProcessLock.inProcessOnly("one-record"))
        assertEquals(listOf("rt-1"), tokens, "one refresh; the other client re-read the store")
    }

    @Test
    fun `positive control - without a shared lock two clients both present the same refresh token`(): Unit = runBlocking(Dispatchers.Default) {
        val tokens = twoClientsRefreshTogether(NoLock, NoLock)
        assertEquals(listOf("rt-1", "rt-1"), tokens, "the second presentation is of a spent token")
    }

    /** Two clients over one store refresh at once; returns the refresh tokens the token endpoint saw. */
    private suspend fun twoClientsRefreshTogether(a: CrossProcessLock, b: CrossProcessLock): List<String?> = coroutineScope {
        val h = signedIn(ClientHarness(lock = a))
        val other = ProtelesClient(h.configuration, h.store, b, h.transport, h.clock)
        h.clock.advance(450)
        h.tokenEndpoint = { delay(300); h.mint(it) }
        listOf(async { h.client.validAccessToken() }, async { other.validAccessToken() }).awaitAll()
        h.tokenRequests.map { it.formValue("refresh_token") }
    }

    @Test
    fun `after taking the cross-process lock the store is re-read - another process may have refreshed`(): Unit = runBlocking {
        val store = RecordingStore()
        lateinit var h: ClientHarness
        var otherProcessRefreshes = false
        val lock = object : CrossProcessLock {
            override suspend fun <T> withLock(action: suspend () -> T): T {
                if (otherProcessRefreshes) {
                    // While this process waited for the lock, the other one refreshed.
                    val s = store.session!!
                    store.session = s.copy(accessToken = "from-the-other-process", refreshToken = "rt-other", obtainedAt = h.clock.epochSeconds())
                }
                return action()
            }
        }
        h = signedIn(ClientHarness(store = store, lock = lock))
        h.clock.advance(450)
        otherProcessRefreshes = true
        assertEquals("from-the-other-process", h.client.validAccessToken())
        assertTrue(h.tokenRequests.isEmpty(), "no refresh: the other process already made it")
    }

    @Test
    fun `a refresh-minted ID token for another subject ends the session`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(450)
        h.idTokenSub = "user-2"
        val e = assertFailsWith<ProtelesException.IdTokenRejected> { h.client.validAccessToken() }
        assertEquals(IdTokenRejection.SUBJECT_CHANGED, e.reason)
        assertNull(h.store.session)
        assertEquals("rt-2", h.transport.requestsTo(REVOKE).single().formValue("token"), "the untrusted family is revoked")
    }

    @Test
    fun `a refresh-minted ID token that fails verification ends the session`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(450)
        h.idTokenExtra = mapOf("at_hash" to IdTokenVerifier.atHash("not-this-one"))
        assertEquals(IdTokenRejection.AT_HASH, assertFailsWith<ProtelesException.IdTokenRejected> { h.client.validAccessToken() }.reason)
        assertNull(h.store.session)
    }

    @Test
    fun `a refresh without an ID token keeps the claims, one without a refresh token keeps the old one`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(450)
        h.issueIdToken = false
        h.issueRefreshToken = false
        assertEquals("at-2", h.client.validAccessToken())
        assertEquals("rt-1", h.store.session!!.refreshToken)
        assertEquals("user-1", h.client.currentClaims()!!.subject)
        assertEquals(1, h.store.writes.size, "nothing rotated, so one write")
    }

    @Test
    fun `expires_in is honoured as sent, not assumed`(): Unit = runBlocking {
        val h = ClientHarness()
        h.expiresIn = 60 // a SAML session deadline can shorten it (§2.3)
        signedIn(h)
        h.clock.advance(29)
        assertEquals("at-1", h.client.validAccessToken())
        h.clock.advance(1)
        assertEquals("at-2", h.client.validAccessToken())
    }

    @Test
    fun `a refresh whose expires_in runs past the end of epoch seconds is held there, not wrapped into expired`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(450)
        h.expiresIn = 1e300
        assertEquals("at-2", h.client.validAccessToken())
        assertEquals(Long.MAX_VALUE, h.store.session!!.expiresAt)
        h.clock.advance(10L * 365 * 86_400)
        assertEquals("at-2", h.client.validAccessToken(), "not rotated on every call")
        assertEquals(1, h.tokenRequests.size)
    }

    @Test
    fun `without a refresh token the access token is used until it expires, then sign-in is required`(): Unit = runBlocking {
        val h = ClientHarness()
        h.issueRefreshToken = false
        signedIn(h)
        h.clock.advance(600)
        assertEquals("at-1", h.client.validAccessToken())
        assertTrue(h.tokenRequests.isEmpty())
        h.clock.advance(300)
        assertFailsWith<ProtelesException.SignInRequired> { h.client.validAccessToken() }
        assertNull(h.store.session)
    }

    @Test
    fun `a device clock set back an hour refreshes, and the session survives the server's timestamps`(): Unit = runBlocking {
        val h = signedIn()
        val idTokenBefore = h.store.session!!.idToken
        h.moveDeviceClock(-3600) // the server's clock does not move: its iat is now an hour "in the future"
        assertEquals("at-2", h.client.validAccessToken())
        assertEquals("rt-2", h.store.session!!.refreshToken)
        assertEquals("user-1", h.client.currentClaims()!!.subject)
        // §10.9 item 2: its exp and iat are no grounds to refuse it — the session
        // goes on — but a token whose times this clock cannot check is not adopted.
        assertEquals(idTokenBefore, h.store.session!!.idToken, "a token whose times this clock cannot check is not adopted")
        assertTrue(h.transport.requestsTo(REVOKE).isEmpty(), "nothing was abandoned")
        assertEquals("at-2", h.client.validAccessToken(), "and it does not refresh again")
        assertEquals(1, h.tokenRequests.size)
    }

    @Test
    fun `a device clock a day fast refreshes, and the session survives the server's timestamps`(): Unit = runBlocking {
        val h = signedIn()
        h.moveDeviceClock(86_400) // every token the server mints now looks expired here
        assertEquals("at-2", h.client.validAccessToken())
        assertEquals("rt-2", h.store.session!!.refreshToken)
        assertEquals("user-1", h.client.currentClaims()!!.subject)
        assertTrue(h.transport.requestsTo(REVOKE).isEmpty())
        h.moveDeviceClock(450)
        assertEquals("at-3", h.client.validAccessToken())
    }

    @Test
    fun `every trust rule a refresh-minted ID token fails ends the session at once, while the stored token is still valid (10_9 item 1)`(): Unit =
        runBlocking {
            val cases = listOf<Pair<IdTokenRejection, ClientHarness.() -> Unit>>(
                IdTokenRejection.SIGNATURE to { signRefreshWith(SigningKey(key.kid)) }, // another key under the same kid
                IdTokenRejection.NO_USABLE_KEY to { signRefreshWith(SigningKey("nobody-publishes-this")) }, // the refetched set lacks it
                IdTokenRejection.ISSUER to { idTokenExtra = mapOf("iss" to "https://evil.example") },
                IdTokenRejection.AUDIENCE to { idTokenExtra = mapOf("aud" to "another-client") },
                IdTokenRejection.AT_HASH to { idTokenExtra = mapOf("at_hash" to IdTokenVerifier.atHash("not-this-one")) },
                IdTokenRejection.SUBJECT_CHANGED to { idTokenSub = "user-2" },
            )
            for ((reason, breakIt) in cases) {
                val h = signedIn()
                h.clock.advance(450) // half-life: a failure of any other kind would return at-1
                h.breakIt()
                assertEquals(reason, assertFailsWith<ProtelesException.IdTokenRejected>("$reason") { h.client.validAccessToken() }.reason)
                assertNull(h.store.session, "$reason: the store is cleared")
                assertEquals("rt-2", h.transport.requestsTo(REVOKE).single().formValue("token"), "$reason: the family is revoked")
                assertFailsWith<ProtelesException.SignInRequired>("$reason") { h.client.validAccessToken() }
                assertEquals(1, h.tokenRequests.size, "$reason: never refreshed again")
            }
        }

    @Test
    fun `a sign-out made without the lock during a refresh stands - the rotation is revoked, not written back`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(450)
        h.tokenEndpoint = { request ->
            // Another process, which could not take the lock in time, signs out meanwhile (§10.9 item 9).
            h.store.session = null
            h.mint(request)
        }
        assertFailsWith<ProtelesException.SignInRequired> { h.client.validAccessToken() }
        assertNull(h.store.session, "the sign-out stands")
        assertEquals("rt-2", h.transport.requestsTo(REVOKE).single().formValue("token"), "the family nobody holds is revoked")
    }

    @Test
    fun `when the lock cannot be taken in time, a refresh re-reads the store and returns a usable token (10_9 item 9)`(): Unit = runBlocking {
        val store = RecordingStore()
        lateinit var h: ClientHarness
        // While this process waited, the one holding the lock refreshed.
        val lock = UnavailableLock(whileWaiting = {
            store.session = store.session!!.copy(accessToken = "from-the-other-process", refreshToken = "rt-other", obtainedAt = h.clock.epochSeconds())
        })
        h = ClientHarness(store = store, lock = NoLock)
        signedIn(h)
        val locked = ProtelesClient(h.configuration, store, lock, h.transport, h.clock)
        h.clock.advance(450)
        assertEquals("from-the-other-process", locked.validAccessToken())
        assertTrue(h.tokenRequests.isEmpty())

        // Nothing usable there: the stored token has expired, and nobody refreshed it.
        val stuck = ProtelesClient(h.configuration, store, UnavailableLock(), h.transport, h.clock)
        h.clock.advance(900)
        val e = assertFailsWith<ProtelesException.Network> { stuck.validAccessToken() }
        assertTrue(e.message!!.contains("timed out"), e.message)
        assertTrue(h.tokenRequests.isEmpty(), "no refresh without the lock")

        // A lock that fails with something other than a ProtelesException is storage.
        val broken = ProtelesClient(h.configuration, store, UnavailableLock(IOException("EACCES")), h.transport, h.clock)
        assertFailsWith<ProtelesException.Storage> { broken.validAccessToken() }
        assertNotNull(store.session, "a lock failure never ends the session")
    }

    @Test
    fun `a store shared across processes with an in-process lock is refused at construction (10_9 item 9)`() {
        val shared = object : TokenStore by InMemoryTokenStore() {
            override val sharedAcrossProcesses: Boolean get() = true
        }
        val configuration = ProtelesConfiguration(ISSUER, CLIENT_ID, REDIRECT)
        val e = assertFailsWith<ProtelesException.Configuration> {
            ProtelesClient(configuration, shared, CrossProcessLock.inProcessOnly("shared-record"))
        }
        assertTrue(e.message!!.contains("cross-process lock"), e.message)
        // A lock that excludes other processes is what it needs; a private store needs none.
        ProtelesClient(configuration, shared, NoLock)
        ProtelesClient(configuration, InMemoryTokenStore(), CrossProcessLock.inProcessOnly("private-record"))
        assertEquals(false, CrossProcessLock.inProcessOnly("x").excludesOtherProcesses)
    }

    @Test
    fun `with the clock skewed, a trust failure still ends the session`(): Unit = runBlocking {
        val h = signedIn()
        h.moveDeviceClock(-3600)
        h.idTokenExtra = mapOf("at_hash" to IdTokenVerifier.atHash("not-this-one"))
        assertEquals(IdTokenRejection.AT_HASH, assertFailsWith<ProtelesException.IdTokenRejected> { h.client.validAccessToken() }.reason)
        assertNull(h.store.session)
    }

    @Test
    fun `nobody signed in is sign-in required`(): Unit = runBlocking {
        val h = ClientHarness()
        assertFailsWith<ProtelesException.SignInRequired> { h.client.validAccessToken() }
        assertTrue(h.transport.requests.isEmpty())
    }

    @Test
    fun `a 200 refused after the server rotated still keeps the new refresh token`(): Unit = runBlocking {
        for (body in listOf(
            mapOf("access_token" to "x", "token_type" to "Bearer", "refresh_token" to "rt-new"), // no expires_in (only RECOMMENDED)
            mapOf("access_token" to "x", "token_type" to "DPoP", "expires_in" to 900, "refresh_token" to "rt-new"),
            mapOf("access_token" to "x", "token_type" to "Bearer", "expires_in" to 900, "refresh_token" to "rt-new", "scope" to 7),
            mapOf("token_type" to "Bearer", "expires_in" to 900, "refresh_token" to "rt-new"),
        )) {
            val h = signedIn()
            h.clock.advance(450)
            h.tokenEndpoint = { ok(body) }
            assertEquals("at-1", h.client.validAccessToken(), "$body: the stored token is still valid")
            assertEquals("rt-new", h.store.writes.first().refreshToken, "$body: persisted first")
            assertEquals("rt-new", h.store.session!!.refreshToken)

            h.clock.advance(ProtelesClient.REFRESH_RETRY_SECONDS)
            h.tokenEndpoint = { h.mint(it) }
            h.client.validAccessToken()
            assertEquals("rt-new", h.tokenRequests.last().formValue("refresh_token"), "$body: the next refresh presents it")
        }
    }

    @Test
    fun `a malformed token response is an invalid_response`(): Unit = runBlocking {
        val h = signedIn()
        h.clock.advance(900) // expired: nothing to fall back on
        for (body in listOf(
            mapOf("access_token" to "x", "token_type" to "DPoP", "expires_in" to 900),
            mapOf("access_token" to "x", "token_type" to "Bearer"),
            mapOf("token_type" to "Bearer", "expires_in" to 900),
            mapOf("access_token" to "x", "token_type" to "Bearer", "expires_in" to 900, "refresh_token" to 5),
            // Expired on arrival, or "never expires" to some libraries: refused, as on iOS.
            mapOf("access_token" to "x", "token_type" to "Bearer", "expires_in" to 0),
            mapOf("access_token" to "x", "token_type" to "Bearer", "expires_in" to -60),
        )) {
            h.tokenEndpoint = { ok(body) }
            assertEquals("invalid_response", assertFailsWith<ProtelesException.TokenEndpointError> { h.client.validAccessToken() }.error)
        }
        h.tokenEndpoint = { HttpResponse(200, emptyMap(), "<html>".toByteArray()) }
        assertEquals("invalid_response", assertFailsWith<ProtelesException.TokenEndpointError> { h.client.validAccessToken() }.error)
        assertNotNull(h.store.session)
    }
}
