package com.proteles.auth

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import java.io.IOException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** docs/mobile-SDKs.md §10.4. */
class SignOutTest {
    private suspend fun signedIn(h: ClientHarness = ClientHarness()): ClientHarness {
        h.client.signIn(h.browser())
        h.transport.requests.clear()
        return h
    }

    @Test
    fun `sign-out revokes the refresh token and clears the store`(): Unit = runBlocking {
        val h = signedIn()
        val result = h.client.signOut()
        assertSame(SignOutResult.Revocation.Revoked, result.revocation)
        assertNull(result.endSession)
        val revoke = h.transport.requestsTo(REVOKE).single()
        assertEquals(
            mapOf("token" to listOf("rt-1"), "token_type_hint" to listOf("refresh_token"), "client_id" to listOf(CLIENT_ID)),
            revoke.form(),
        )
        assertNull(revoke.headers["Authorization"])
        assertNull(h.store.session)
        assertNull(h.client.currentClaims())
        assertFailsWith<ProtelesException.SignInRequired> { h.client.validAccessToken() }
    }

    @Test
    fun `the store is cleared even when revocation is refused, and the failure is reported`(): Unit = runBlocking {
        val h = signedIn()
        h.transport.on("POST", REVOKE) { status(400, mapOf("error" to "invalid_client")) }
        val refused = assertIs<SignOutResult.Revocation.Failed>(h.client.signOut().revocation)
        assertEquals("invalid_client", assertIs<ProtelesException.TokenEndpointError>(refused.error).error)
        assertNull(h.store.session)

        val again = signedIn()
        again.transport.on("POST", REVOKE) { status(503) }
        val unavailable = assertIs<SignOutResult.Revocation.Failed>(again.client.signOut().revocation)
        assertEquals(503, assertIs<ProtelesException.Network>(unavailable.error).httpStatus, "a 5xx is try-later, not a refusal")
        assertNull(again.store.session)
    }

    @Test
    fun `a sign-out cancelled while another process holds the lock still revokes and clears`(): Unit = runBlocking {
        val lock = HeldLock()
        val h = signedIn(ClientHarness(lock = lock))
        lock.held = true
        val caller = launch { h.client.signOut() }
        lock.waiting.await()
        caller.cancel() // the screen that asked was closed
        lock.release.complete(Unit)
        caller.join()
        assertEquals("rt-1", h.transport.requestsTo(REVOKE).single().formValue("token"))
        assertNull(h.store.session, "signed out on this device, as asked")
    }

    @Test
    fun `a sign-out cancelled mid-revocation lets the revocation finish`(): Unit = runBlocking {
        val h = signedIn()
        val inFlight = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var answered = false
        h.transport.on("POST", REVOKE) { inFlight.complete(Unit); release.await(); answered = true; status(200) }
        val caller = launch { h.client.signOut() }
        inFlight.await()
        caller.cancel()
        release.complete(Unit)
        caller.join()
        assertTrue(answered, "the server was told")
        assertNull(h.store.session)
    }

    @Test
    fun `the store is cleared first, then the refresh token revoked (10_9 item 6)`(): Unit = runBlocking {
        val h = signedIn()
        val storedAtEachRevocation = mutableListOf<StoredSession?>()
        h.transport.on("POST", REVOKE) {
            storedAtEachRevocation.add(h.store.session)
            status(200)
        }
        assertSame(SignOutResult.Revocation.Revoked, h.client.signOut().revocation)
        assertEquals(1, storedAtEachRevocation.size, "one revocation")
        assertNull(storedAtEachRevocation.single(), "the device was signed out before the server was asked")
        assertEquals(1, h.store.clears)
    }

    @Test
    fun `a record that cannot be read is a failed revocation, not nothing to revoke`(): Unit = runBlocking {
        val h = signedIn()
        h.store.failReads = true
        val failed = assertIs<SignOutResult.Revocation.Failed>(h.client.signOut().revocation)
        assertIs<ProtelesException.Storage>(failed.error)
        assertEquals(1, h.store.clears, "cleared anyway")
        assertTrue(h.transport.requestsTo(REVOKE).isEmpty())
    }

    @Test
    fun `a record that can never be read is deleted, and reported as a storage failure (10_9 item 6)`(): Unit = runBlocking {
        val h = signedIn()
        h.store.unreadable = true
        val failed = assertIs<SignOutResult.Revocation.Failed>(h.client.signOut().revocation)
        assertIs<ProtelesException.Storage>(failed.error)
        assertEquals(1, h.store.clears, "deleted")
        assertTrue(h.transport.requestsTo(REVOKE).isEmpty())
    }

    @Test
    fun `when the lock cannot be taken in time, sign-out clears and revokes anyway (10_9 item 9)`(): Unit = runBlocking {
        val h = ClientHarness()
        h.client.signIn(h.browser())
        val lock = UnavailableLock()
        val locked = ProtelesClient(h.configuration, h.store, lock, h.transport, h.clock)
        assertSame(SignOutResult.Revocation.Revoked, locked.signOut().revocation)
        assertEquals(1, lock.attempts)
        assertNull(h.store.session)
        assertEquals("rt-1", h.transport.requestsTo(REVOKE).single().formValue("token"))
    }

    @Test
    fun `the store is cleared even when the server cannot be reached`(): Unit = runBlocking {
        val h = signedIn()
        h.transport.on("POST", REVOKE) { throw IOException("offline") }
        val result = h.client.signOut()
        assertIs<ProtelesException.Network>(assertIs<SignOutResult.Revocation.Failed>(result.revocation).error)
        assertNull(h.store.session)
    }

    @Test
    fun `the store is cleared even when discovery itself fails`(): Unit = runBlocking {
        val h = ClientHarness()
        h.client.signIn(h.browser())
        // A fresh client in a process that never reached discovery, offline.
        val cold = ClientHarness(store = h.store)
        cold.transport.on("GET", DISCOVERY) { throw IOException("offline") }
        val result = cold.client.signOut()
        assertIs<SignOutResult.Revocation.Failed>(result.revocation)
        assertNull(h.store.session)
    }

    @Test
    fun `a stored refresh token this client knows is dead is still revoked at sign-out`(): Unit = runBlocking {
        val h = signedIn()
        // A refresh-minted ID token for another subject abandons the session
        // (10_9 item 1) — but the store cannot be cleared and the device is
        // offline, so the family's revocation fails and its token stays on disk.
        h.clock.advance(450)
        h.idTokenSub = "user-2"
        h.store.failClears = true
        h.transport.on("POST", REVOKE) { throw IOException("offline") }
        assertFailsWith<ProtelesException.IdTokenRejected> { h.client.validAccessToken() }
        assertEquals("rt-2", h.store.session?.refreshToken, "the abandoned family is still on disk")
        assertNull(h.client.currentClaims(), "and reads as signed out")

        // Back online, the person signs out: the family is ended server-side.
        h.store.failClears = false
        h.transport.on("POST", REVOKE) { status(200) }
        h.transport.requests.clear()
        assertSame(SignOutResult.Revocation.Revoked, h.client.signOut().revocation)
        assertEquals("rt-2", h.transport.requestsTo(REVOKE).single().formValue("token"))
        assertNull(h.store.session)
        assertTrue(h.tokenRequests.isEmpty(), "revoked, never presented to the token endpoint")
    }

    @Test
    fun `nothing stored means nothing to revoke and no request`(): Unit = runBlocking {
        val h = ClientHarness()
        val result = h.client.signOut()
        assertSame(SignOutResult.Revocation.NothingToRevoke, result.revocation)
        assertTrue(h.transport.requests.isEmpty())
    }

    @Test
    fun `a store that cannot be cleared is the one failure sign-out raises - and the token is still revoked (10_9 item 6)`(): Unit =
        runBlocking {
            val h = signedIn()
            h.store.failClears = true
            assertFailsWith<ProtelesException.Storage> { h.client.signOut() }
            assertEquals("rt-1", h.transport.requestsTo(REVOKE).single().formValue("token"), "revoked although the store kept it")
            assertNull(h.client.currentClaims(), "the stale record reads as signed out here")
            assertFailsWith<ProtelesException.SignInRequired> { h.client.validAccessToken() }
            assertTrue(h.tokenRequests.isEmpty(), "and its revoked token is never presented")

            // Offline as well: the storage error is raised, the revocation's failure suppressed into it.
            val again = signedIn()
            again.store.failClears = true
            again.transport.on("POST", REVOKE) { throw IOException("offline") }
            val e = assertFailsWith<ProtelesException.Storage> { again.client.signOut() }
            assertTrue(e.suppressed.any { it is ProtelesException.Network }, e.suppressed.toList().toString())
        }

    @Test
    fun `ending the browser session sends id_token_hint, client_id, post_logout_redirect_uri and state, after clearing`(): Unit = runBlocking {
        val h = signedIn()
        val idToken = h.store.session!!.idToken!!
        var storeAtBrowserTime: StoredSession? = h.store.session
        val browser = FakeBrowser { url, returnUri ->
            storeAtBrowserTime = h.store.session
            assertEquals(POST_LOGOUT, returnUri)
            "$POST_LOGOUT?state=${queryOf(url)["state"]!!.single()}"
        }
        val result = h.client.signOut(endSession = browser)
        assertSame(SignOutResult.Revocation.Revoked, result.revocation)
        assertSame(SignOutResult.EndSession.Completed, result.endSession)
        assertNull(storeAtBrowserTime, "local sign-out does not wait for the browser")

        val url = browser.opened.single()
        assertTrue(url.startsWith("$END_SESSION?"), url)
        val q = queryOf(url)
        assertEquals(setOf("id_token_hint", "client_id", "post_logout_redirect_uri", "state"), q.keys)
        assertEquals(idToken, q["id_token_hint"]!!.single())
        assertEquals(CLIENT_ID, q["client_id"]!!.single())
        assertEquals(POST_LOGOUT, q["post_logout_redirect_uri"]!!.single())
        assertEquals(43, q["state"]!!.single().length)
    }

    @Test
    fun `an end-session return with another state is reported, the local sign-out stands`(): Unit = runBlocking {
        val h = signedIn()
        val result = h.client.signOut(endSession = FakeBrowser { _, _ -> "$POST_LOGOUT?state=forged" })
        assertIs<ProtelesException.StateMismatch>(assertIs<SignOutResult.EndSession.Failed>(result.endSession).error)
        assertNull(h.store.session)
    }

    @Test
    fun `closing the browser during end-session is Dismissed`(): Unit = runBlocking {
        val h = signedIn()
        val result = h.client.signOut(endSession = FakeBrowser { _, _ -> throw ProtelesException.Cancelled() })
        assertSame(SignOutResult.EndSession.Dismissed, result.endSession)
        assertNull(h.store.session)
    }

    @Test
    fun `without a post-logout redirect the browser is told nothing comes back`(): Unit = runBlocking {
        val h = signedIn(ClientHarness(configuration = ProtelesConfiguration(ISSUER, CLIENT_ID, REDIRECT)))
        var returnSeen: String? = "unset"
        val browser = FakeBrowser { _, returnUri ->
            returnSeen = returnUri
            throw ProtelesException.Cancelled()
        }
        val result = h.client.signOut(endSession = browser)
        assertNull(returnSeen)
        assertSame(SignOutResult.EndSession.Dismissed, result.endSession)
        val q = queryOf(browser.opened.single())
        assertTrue("post_logout_redirect_uri" !in q)
    }

    @Test
    fun `an issuer without an end_session_endpoint reports it`(): Unit = runBlocking {
        val h = signedIn(ClientHarness(discovery = discoveryDocument(endSession = false)))
        val result = h.client.signOut(endSession = FakeBrowser { _, _ -> error("must not open") })
        assertIs<ProtelesException.Configuration>(assertIs<SignOutResult.EndSession.Failed>(result.endSession).error)
        assertNull(h.store.session)
    }
}
