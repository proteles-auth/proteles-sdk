package com.proteles.auth.live

import com.proteles.auth.CrossProcessLock
import com.proteles.auth.IdTokenRejection
import com.proteles.auth.ProtelesClient
import com.proteles.auth.ProtelesConfiguration
import com.proteles.auth.ProtelesException
import com.proteles.auth.ProviderMetadata
import com.proteles.auth.SignOutResult
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.MethodOrderer
import org.junit.jupiter.api.Order
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.TestMethodOrder
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The SDK against a real Proteles server (docs/mobile-SDKs.md §10.8): the real
 * [ProtelesClient] with its own transport, a real login form behind
 * [HttpBrowser], the real key set, and the server asked directly ([ServerProbe])
 * what it now thinks of each token the SDK holds or gave up.
 *
 * Run it under mobile/live/run-live.sh, which starts and seeds the server:
 *
 *     mobile/live/run-live.sh -- mobile/android/gradlew -p mobile/android :core:liveTest
 *
 * The steps run in order and share one browser (one cookie jar, one login), one
 * store and one client, as one app does. Each prints what it saw — statuses,
 * claims and lengths, never a token or the password.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation::class)
@EnabledIfEnvironmentVariable(named = "PROTELES_LIVE_ISSUER", matches = ".+")
class LiveServerTest {
    private val server = LiveServer.fromEnvironment()
    private val probe = ServerProbe(server)
    private val configuration = ProtelesConfiguration(
        server.issuer,
        server.clientId,
        server.redirectUri,
        postLogoutRedirectUri = server.postLogoutRedirectUri,
    )

    /** One browser for the whole run: its session cookie is what makes later sign-ins silent. */
    private val browser = HttpBrowser(server.username, server.password)

    private val store = SharedMemoryStore()
    private val lockKey = "live-test-${System.identityHashCode(store)}"
    private val clock = OffsetClock()
    private val transport = RecordingTransport()
    private val client = ProtelesClient(configuration, store, CrossProcessLock.inProcessOnly(lockKey), transport, clock)

    private lateinit var metadata: ProviderMetadata
    private lateinit var subject: String

    /**
     * How far past an access token's half-life the clock is moved to force a
     * refresh: half the `expires_in` the server sent at sign-in (run-live.sh can
     * shorten it), and ten seconds more.
     */
    private var pastHalfLife: Long = 0

    /** The refresh tokens the session has held, oldest first. */
    private val refreshTokens = mutableListOf<String>()

    private fun say(line: String) = println("  live: $line")

    private fun storedRefreshToken(): String = assertNotNull(store.stored("refreshToken"), "the store holds a refresh token")

    private fun storedAccessToken(): String = assertNotNull(store.stored("accessToken"), "the store holds an access token")

    // --- sign-in -----------------------------------------------------------

    @Test
    @Order(1)
    fun `discovery names the configured issuer byte for byte, and every endpoint is on it`() = runBlocking<Unit> {
        metadata = client.providerMetadata()
        assertEquals(server.issuer, metadata.issuer)
        val endpoints = listOf(
            metadata.authorizationEndpoint,
            metadata.tokenEndpoint,
            metadata.jwksUri,
            assertNotNull(metadata.revocationEndpoint, "revocation_endpoint"),
            assertNotNull(metadata.endSessionEndpoint, "end_session_endpoint"),
        )
        for (e in endpoints) assertTrue(e.startsWith("${server.issuer}/"), "$e is on the issuer")
        assertEquals(1, transport.to("${server.issuer}/.well-known/openid-configuration").size, "discovery fetched once")
        say("issuer ${metadata.issuer}; token ${metadata.tokenEndpoint}; jwks ${metadata.jwksUri}")
    }

    @Test
    @Order(2)
    fun `sign-in - PKCE, the real login form, the callback's state and iss, the code exchange, the ID token`() = runBlocking<Unit> {
        val claims = client.signIn(browser)
        subject = claims.subject

        // The authorization request the SDK built (§10.2 steps 2–3).
        val authorizationUrl = browser.opened.single()
        assertTrue(authorizationUrl.startsWith("${metadata.authorizationEndpoint}?"), "opened the discovered authorization endpoint")
        val request = queryOf(authorizationUrl)
        assertEquals("code", request["response_type"])
        assertEquals(server.clientId, request["client_id"])
        assertEquals(server.redirectUri, request["redirect_uri"])
        assertEquals("openid profile email", request["scope"])
        assertEquals("S256", request["code_challenge_method"])
        for (name in listOf("state", "nonce", "code_challenge")) assertEquals(43, request[name]?.length, "$name is 32 bytes, base64url")
        assertNull(request["login_hint"], "no login_hint (P2.12)")
        say("browser: ${browser.trace.joinToString("; ")}")
        assertEquals(1, browser.logins, "the login form was filled in once")
        assertEquals(0, browser.consents, "no consent page for a first-party client")

        // The callback the server sent (§10.2 step 4), which the SDK accepted.
        val callback = queryOf(browser.returned.single())
        assertEquals(server.issuer, callback["iss"], "the callback's iss is the issuer, byte for byte (RFC 9207)")
        assertEquals(request["state"], callback["state"], "the callback's state is the one sent")
        val code = assertNotNull(callback["code"])

        // The code exchange (§10.2 step 5): a public client, the identical redirect URI, the verifier.
        val exchange = transport.tokenRequests(metadata.tokenEndpoint, "authorization_code").single()
        assertEquals(200, exchange.response.status, "the code exchange: ${exchange.body.take(200)}")
        val form = exchange.form
        assertEquals(code, form["code"])
        assertEquals(server.redirectUri, form["redirect_uri"])
        assertEquals(server.clientId, form["client_id"])
        assertEquals(request["code_challenge"], s256(assertNotNull(form["code_verifier"])), "the verifier matches the challenge (S256)")
        assertEquals(setOf("grant_type", "code", "redirect_uri", "client_id", "code_verifier"), form.keys, "no client secret")
        assertFalse(exchange.request.headers.keys.any { it.equals("Authorization", ignoreCase = true) }, "no client authentication header")

        // The ID token (§10.2 step 6): verified against the real key set, with this
        // login's nonce and the access token from the same response.
        val jwks = transport.to(metadata.jwksUri)
        assertEquals(listOf(200), jwks.map { it.response.status }, "the real key set, fetched once")
        val accessToken = assertNotNull(jsonString(exchange.body, "access_token"))
        val idToken = assertNotNull(jsonString(exchange.body, "id_token"))
        assertEquals(request["nonce"], claims.nonce, "the nonce is this request's")
        assertEquals(atHashOf(accessToken), claims["at_hash"], "at_hash is this response's access token")
        assertEquals(server.issuer, claims.issuer)
        assertEquals(listOf(server.clientId), claims.audience)
        say("ID token: sub=${claims.subject} aud=${claims.audience} nonce matches, at_hash matches, exp-iat=${(claims.expiresAt ?: 0) - (claims.issuedAt ?: 0)}s, amr=${claims.amr}, acr=${claims.acr}")

        // Persisted before signIn returned (§10.2 step 7).
        assertEquals(accessToken, storedAccessToken())
        assertEquals(idToken, store.stored("idToken"), "the verified ID token is the stored one")
        val refreshToken = storedRefreshToken()
        assertEquals(jsonString(exchange.body, "refresh_token"), refreshToken, "the issued refresh token is the stored one")
        refreshTokens += refreshToken
        pastHalfLife = assertNotNull(jsonNumber(exchange.body, "expires_in"), "expires_in") / 2 + 10
        say("code exchange: HTTP 200, expires_in=${jsonNumber(exchange.body, "expires_in")}, scope=${jsonString(exchange.body, "scope")}, refresh token issued without offline_access")
    }

    @Test
    @Order(3)
    fun `currentClaims and isSignedIn show the seeded person, as userinfo does`() = runBlocking<Unit> {
        assertTrue(client.isSignedIn())
        val claims = assertNotNull(client.currentClaims())
        assertEquals(subject, claims.subject)
        assertEquals(server.username, claims.preferredUsername, "preferred_username is the seeded user (profile scope)")
        val email = assertNotNull(claims.email, "email (email scope)")
        val info = probe.userinfo(storedAccessToken())
        assertEquals(200, info.status, "userinfo: $info")
        assertEquals(subject, info.string("sub"), "userinfo names the same subject")
        assertEquals(server.username, info.string("preferred_username"))
        assertEquals(email, info.string("email"))
        say("currentClaims: sub=${claims.subject} preferred_username=${claims.preferredUsername} email=${claims.email} email_verified=${claims.emailVerified} auth_time=${claims.authTime}")
    }

    @Test
    @Order(4)
    fun `validAccessToken returns a token the server accepts, without a refresh before half-life`() = runBlocking<Unit> {
        val before = transport.exchanges.size
        val token = client.validAccessToken()
        assertEquals(storedAccessToken(), token)
        assertEquals(before, transport.exchanges.size, "no request: the token is not yet half-way through its life")
        val accepted = probe.userinfo(token)
        assertEquals(200, accepted.status, "userinfo accepts it: $accepted")
        // The control: the same endpoint refuses a token that is not one.
        val refused = probe.userinfo("${token.dropLast(4)}AAAA")
        assertEquals(401, refused.status, "userinfo refuses a tampered token: $refused")
        say("userinfo with validAccessToken(): HTTP ${accepted.status}; with a tampered token: HTTP ${refused.status}")
    }

    // --- refresh -------------------------------------------------------------

    @Test
    @Order(5)
    fun `past half-life the refresh rotates, and the server then refuses the old refresh token`() = runBlocking<Unit> {
        val oldAccess = storedAccessToken()
        val oldRefresh = storedRefreshToken()
        val authTime = assertNotNull(client.currentClaims()).authTime
        clock.offsetSeconds += pastHalfLife

        val token = client.validAccessToken()

        val refresh = transport.tokenRequests(metadata.tokenEndpoint, "refresh_token").single()
        assertEquals(200, refresh.response.status, "the refresh: ${refresh.body.take(200)}")
        assertEquals(mapOf("grant_type" to "refresh_token", "refresh_token" to oldRefresh, "client_id" to server.clientId), refresh.form)
        assertNotEquals(oldAccess, token, "a new access token")
        assertEquals(jsonString(refresh.body, "access_token"), token)
        val newRefresh = storedRefreshToken()
        assertNotEquals(oldRefresh, newRefresh, "the refresh token rotated")
        assertEquals(jsonString(refresh.body, "refresh_token"), newRefresh, "the rotated token is the stored one (persisted before return)")
        assertEquals(token, storedAccessToken())
        refreshTokens += newRefresh

        // The refresh-minted ID token was verified (null nonce, the new at_hash, the same sub) and adopted.
        val claims = assertNotNull(client.currentClaims())
        assertEquals(subject, claims.subject)
        assertNull(claims.nonce, "the refresh grant mints no nonce")
        assertEquals(atHashOf(token), claims["at_hash"], "the adopted claims are the refresh-minted ID token's")
        assertEquals(authTime, claims.authTime, "auth_time inherited, not restamped (trap 8)")

        // The server's view of both refresh tokens, and of the new access token.
        assertEquals(200, probe.userinfo(token).status, "userinfo accepts the refreshed access token")
        val replay = probe.refresh(oldRefresh)
        assertEquals(400 to "invalid_grant", replay.status to replay.string("error"), "the old refresh token is refused: ${replay.body}")
        say("refresh: HTTP 200, rotated; the old refresh token now: $replay (${replay.string("error_description")})")

        // Nothing more until the next half-life.
        val before = transport.exchanges.size
        assertEquals(token, client.validAccessToken())
        assertEquals(before, transport.exchanges.size, "the fresh token is used as it is")
    }

    @Test
    @Order(6)
    fun `a second client over the same store sees the session, and each sees the other's rotation`() = runBlocking<Unit> {
        // One process, one clock: the second client shares the first one's.
        val otherTransport = RecordingTransport()
        val other = ProtelesClient(configuration, store, CrossProcessLock.inProcessOnly(lockKey), otherTransport, clock)

        assertTrue(other.isSignedIn())
        assertEquals(subject, assertNotNull(other.currentClaims()).subject)
        assertEquals(storedAccessToken(), other.validAccessToken(), "the stored token, as it is")
        assertTrue(otherTransport.exchanges.none { it.request.url.contains("/token") }, "no token request")

        // The second client refreshes: it presents the stored refresh token.
        val held = storedRefreshToken()
        clock.offsetSeconds += pastHalfLife
        val otherToken = other.validAccessToken()
        val otherRefresh = otherTransport.tokenRequests(metadata.tokenEndpoint, "refresh_token").single()
        assertEquals(held, otherRefresh.form["refresh_token"])
        assertEquals(200, otherRefresh.response.status, "the second client's refresh: ${otherRefresh.body.take(200)}")
        val rotated = storedRefreshToken()
        assertNotEquals(held, rotated)
        refreshTokens += rotated

        // The first client reads the store: it uses the second client's token, and sends nothing.
        val before = transport.exchanges.size
        assertEquals(otherToken, client.validAccessToken())
        assertEquals(before, transport.exchanges.size, "the first client did not refresh again")

        // And when it is due, it refreshes with the second client's rotation, not the token it last held itself.
        clock.offsetSeconds += pastHalfLife
        val token = client.validAccessToken()
        val refresh = transport.tokenRequests(metadata.tokenEndpoint, "refresh_token").last()
        assertEquals(rotated, refresh.form["refresh_token"], "the first client presented the rotation the second one stored")
        assertEquals(200, refresh.response.status, "the first client's refresh: ${refresh.body.take(200)}")
        assertEquals(token, other.validAccessToken(), "…and the second client sees that one")
        refreshTokens += storedRefreshToken()
        say("second client: saw sub ${other.currentClaims()?.subject}; its refresh and then the first client's both HTTP 200, each presenting the other's rotation")
    }

    // --- sign-out ------------------------------------------------------------

    @Test
    @Order(7)
    fun `sign-out revokes, the server then refuses the refresh token, and validAccessToken needs a sign-in`() = runBlocking<Unit> {
        val refreshToken = storedRefreshToken()
        val accessToken = storedAccessToken()
        assertEquals(200, probe.userinfo(accessToken).status, "the control: userinfo accepts the access token before sign-out")

        val result = client.signOut()

        assertEquals(SignOutResult.Revocation.Revoked, result.revocation, "revoked: $result")
        assertNull(result.endSession)
        val revocation = transport.to(assertNotNull(metadata.revocationEndpoint)).single()
        assertEquals(mapOf("token" to refreshToken, "token_type_hint" to "refresh_token", "client_id" to server.clientId), revocation.form)
        assertEquals(200, revocation.response.status)
        assertNull(store.stored("refreshToken"), "the store is cleared")
        assertFalse(client.isSignedIn())
        assertNull(client.currentClaims())

        val refused = probe.refresh(refreshToken)
        assertEquals(400 to "invalid_grant", refused.status to refused.string("error"), "the revoked refresh token: ${refused.body}")
        assertFailsWith<ProtelesException.SignInRequired> { client.validAccessToken() }
        val other = ProtelesClient(configuration, store, CrossProcessLock.inProcessOnly(lockKey), RecordingTransport(), clock)
        assertFailsWith<ProtelesException.SignInRequired> { other.validAccessToken() }

        // Every refresh token this session held is dead now.
        for ((i, token) in refreshTokens.withIndex()) {
            val answer = probe.refresh(token)
            assertEquals(400 to "invalid_grant", answer.status to answer.string("error"), "refresh token #${i + 1} of the session")
        }
        // §10.4 sends only the refresh token, but the server ends the grant with it
        // (RFC 7009 §2.1, docs/mobile-SDKs.md §10.4): its own
        // endpoints refuse the grant's access tokens from now on — as the README says.
        val afterSignOut = probe.userinfo(accessToken)
        assertEquals(401, afterSignOut.status, "userinfo refuses the signed-out grant's access token: $afterSignOut")
        say("sign-out: $result; the refresh token now: $refused; all ${refreshTokens.size} of the session's refresh tokens refused; " +
            "userinfo with the last access token: HTTP 200 before, HTTP ${afterSignOut.status} after")
    }

    // --- the checks, shown to be what accepted the real answers ---------------

    /**
     * A sign-in on a fresh client and store, through a transport [setUp] can make
     * tamper with responses, and a browser that can rewrite what it opens or
     * returns. The browser session is the run's, so no login form is shown.
     */
    private suspend fun signInThrough(setUp: RecordingTransport.() -> Unit = {}, rewriteOpened: ((String) -> String)? = null, rewriteReturned: ((String) -> String)? = null): Pair<Result<*>, RecordingTransport> {
        val recording = RecordingTransport().apply(setUp)
        val probeClient = ProtelesClient(configuration, SharedMemoryStore(), CrossProcessLock.inProcessOnly("$lockKey-probe"), recording, OffsetClock())
        browser.rewriteOpened = rewriteOpened
        browser.rewriteReturned = rewriteReturned
        return try {
            runCatching { probeClient.signIn(browser) } to recording
        } finally {
            browser.rewriteOpened = null
            browser.rewriteReturned = null
        }
    }

    /** The refresh token the server issued on [recording]'s code exchange was revoked by the SDK, and the server agrees (§10.9 item 7). */
    private fun assertRevokedAfterRefusal(recording: RecordingTransport, what: String) {
        val issued = assertNotNull(jsonString(recording.tokenRequests(metadata.tokenEndpoint, "authorization_code").single().body, "refresh_token"))
        val revocation = recording.to(assertNotNull(metadata.revocationEndpoint)).single()
        assertEquals(issued, revocation.form["token"], "$what: the SDK revoked the refresh token it was issued")
        assertEquals(200, revocation.response.status)
        val answer = probe.refresh(issued)
        assertEquals(400 to "invalid_grant", answer.status to answer.string("error"), "$what: the server refuses it now")
    }

    @Test
    @Order(8)
    fun `controls - an ID token with a broken signature is refused against the real key set, and its refresh token revoked`() = runBlocking<Unit> {
        val (result, recording) = signInThrough({
            tamper = { request, response ->
                val body = response.body.toString(Charsets.UTF_8)
                val idToken = jsonString(body, "id_token")
                if (request.bodyText?.contains("grant_type=authorization_code") == true && idToken != null) {
                    withBody(response, replaceJsonString(body, "id_token", withBrokenSignature(idToken)))
                } else {
                    response
                }
            }
        })
        val e = result.exceptionOrNull() as? ProtelesException.IdTokenRejected ?: throw AssertionError("refused as IdTokenRejected: $result")
        assertEquals(IdTokenRejection.SIGNATURE, e.reason)
        assertRevokedAfterRefusal(recording, "broken signature")
        say("broken signature: ${e.reason}; the issued refresh token revoked and refused by the server")
    }

    @Test
    @Order(9)
    fun `controls - a nonce other than the one sent is refused`() = runBlocking<Unit> {
        // The browser asks the server for a different nonce: the server's ID token
        // then carries that one, correctly signed.
        val (result, recording) = signInThrough(
            rewriteOpened = { url -> url.replace(Regex("([?&]nonce=)[^&]*"), "$1${"n".repeat(43)}") },
        )
        val e = result.exceptionOrNull() as? ProtelesException.IdTokenRejected ?: throw AssertionError("refused as IdTokenRejected: $result")
        assertEquals(IdTokenRejection.NONCE, e.reason)
        assertRevokedAfterRefusal(recording, "other nonce")
        say("other nonce: ${e.reason}; the issued refresh token revoked and refused by the server")
    }

    @Test
    @Order(10)
    fun `controls - an access token the ID token's at_hash does not describe is refused`() = runBlocking<Unit> {
        val (result, recording) = signInThrough({
            tamper = { request, response ->
                val body = response.body.toString(Charsets.UTF_8)
                val accessToken = jsonString(body, "access_token")
                if (request.bodyText?.contains("grant_type=authorization_code") == true && accessToken != null) {
                    withBody(response, replaceJsonString(body, "access_token", accessToken.dropLast(4) + "AAAA"))
                } else {
                    response
                }
            }
        })
        val e = result.exceptionOrNull() as? ProtelesException.IdTokenRejected ?: throw AssertionError("refused as IdTokenRejected: $result")
        assertEquals(IdTokenRejection.AT_HASH, e.reason)
        assertRevokedAfterRefusal(recording, "other access token")
        say("other access token: ${e.reason}; the issued refresh token revoked and refused by the server")
    }

    @Test
    @Order(11)
    fun `controls - a callback without iss, or with another state, is refused before any code exchange`() = runBlocking<Unit> {
        val (noIss, r1) = signInThrough(rewriteReturned = { url -> url.replace(Regex("([?&])iss=[^&]*&?"), "$1").trimEnd('&') })
        assertTrue(noIss.exceptionOrNull() is ProtelesException.IssuerMismatch, "no iss: $noIss")
        val (otherState, r2) = signInThrough(rewriteReturned = { url -> url.replace(Regex("([?&]state=)[^&]*"), "$1${"s".repeat(43)}") })
        assertTrue(otherState.exceptionOrNull() is ProtelesException.StateMismatch, "other state: $otherState")
        for (r in listOf(r1, r2)) assertTrue(r.to(metadata.tokenEndpoint).isEmpty(), "no code exchange")
        say("callback without iss: IssuerMismatch; with another state: StateMismatch; no code exchanged")
    }

    // --- ending the browser session --------------------------------------------

    @Test
    @Order(12)
    fun `sign-out with end-session ends the browser session too, and the next sign-in shows the login form`() = runBlocking<Unit> {
        // Back to the real time: a sign-in's ID token is held to the device clock (§5.2).
        clock.offsetSeconds = 0
        val loginsBefore = browser.logins
        client.signIn(browser)
        assertEquals(loginsBefore, browser.logins, "a sign-in on a live browser session is silent")
        val refreshToken = storedRefreshToken()

        val result = client.signOut(endSession = browser)

        assertEquals(SignOutResult.Revocation.Revoked, result.revocation, "revoked: $result")
        assertEquals(SignOutResult.EndSession.Completed, result.endSession, "end-session: $result")
        val endSession = browser.opened.last()
        assertTrue(endSession.startsWith("${metadata.endSessionEndpoint}?"))
        assertEquals(setOf("id_token_hint", "client_id", "post_logout_redirect_uri", "state"), queryOf(endSession).keys)
        assertTrue(browser.returned.last().startsWith("${server.postLogoutRedirectUri}?"), "returned to ${server.postLogoutRedirectUri}")
        val refused = probe.refresh(refreshToken)
        assertEquals(400 to "invalid_grant", refused.status to refused.string("error"))

        // The browser session is over: the next sign-in meets the login form again.
        client.signIn(browser)
        assertEquals(loginsBefore + 1, browser.logins, "the login form was shown again")
        assertEquals(SignOutResult.Revocation.Revoked, client.signOut().revocation)
        say("end-session: $result; browser: ${browser.trace.takeLast(8).joinToString("; ")}")
    }

    // --- a session ended elsewhere ---------------------------------------------

    @Test
    @Order(13)
    fun `a family revoked elsewhere - the real invalid_grant ends the session at once, and the dead token is not sent again`() = runBlocking<Unit> {
        clock.offsetSeconds = 0
        client.signIn(browser)
        val refreshToken = storedRefreshToken()
        // Another holder of the family ends it — an administrator, a support tool.
        val revoked = probe.revoke(refreshToken)
        assertEquals(200, revoked.status, "revoked out of band: $revoked")

        // Past half-life, with the stored access token still unexpired: §10.9 item 1
        // says invalid_grant is never softened into "use the stored token".
        clock.offsetSeconds += pastHalfLife
        val refreshes = { transport.tokenRequests(metadata.tokenEndpoint, "refresh_token") }
        val before = refreshes().size
        val e = assertFailsWith<ProtelesException.SignInRequired> { client.validAccessToken() }

        val refresh = refreshes().drop(before).single()
        assertEquals(refreshToken, refresh.form["refresh_token"])
        assertEquals(400 to "invalid_grant", refresh.response.status to jsonString(refresh.body, "error"), "the server's answer: ${refresh.body}")
        // Walked rather than read one level down: with assertions on (as Gradle runs
        // tests), kotlinx.coroutines' stack-trace recovery re-throws a copy of the
        // exception with the original as its cause — as RefreshTest also allows.
        val chain = generateSequence<Throwable>(e) { it.cause }.toList()
        val cause = chain.filterIsInstance<ProtelesException.TokenEndpointError>().firstOrNull()
            ?: throw AssertionError("caused by the token endpoint's refusal: ${chain.map { it.javaClass.simpleName }}")
        assertEquals("invalid_grant", cause.error)
        assertFalse(client.isSignedIn(), "the session is cleared")
        assertNull(store.stored("refreshToken"))
        assertFailsWith<ProtelesException.SignInRequired> { client.validAccessToken() }
        assertEquals(before + 1, refreshes().size, "the refused token was presented once, never again")
        assertEquals(SignOutResult.Revocation.NothingToRevoke, client.signOut().revocation)
        say("revoked elsewhere: validAccessToken raised ${chain.joinToString(" <- ") { it.javaClass.simpleName }} ($cause); one refresh request, store cleared")
    }
}
