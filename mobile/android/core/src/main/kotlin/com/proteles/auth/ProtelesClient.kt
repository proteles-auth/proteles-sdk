package com.proteles.auth

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.cancellation.CancellationException

/**
 * The native SDK contract (docs/mobile-SDKs.md §10), platform-free.
 *
 * On Android, build it with `ProtelesAndroid.client(context, configuration)`,
 * which supplies the Keystore-backed store and the file lock; the browser hop is
 * passed per call because it needs the Activity in front. Create **one per
 * process** and share it: discovery and the key set are cached on the instance.
 *
 * [crossProcessLock] has no default, because the right one depends on who else
 * holds [store]'s record: it must exclude every process of the app and every
 * other client in this process that uses the same record (§10.6). On Android,
 * `FileCrossProcessLock.forClient(context, clientId)`; in a single-process JVM
 * app, [CrossProcessLock.inProcessOnly] with one key per record.
 *
 * @throws ProtelesException.Configuration when [store] is shared with the app's
 *   other processes and [crossProcessLock] excludes only this one (§10.9 item 9).
 */
public class ProtelesClient(
    public val configuration: ProtelesConfiguration,
    private val store: TokenStore,
    private val crossProcessLock: CrossProcessLock,
    private val transport: Transport = HttpUrlConnectionTransport(),
    private val clock: Clock = Clock.SYSTEM,
    private val random: SecureRandom = SecureRandom(),
) {
    init {
        // §10.9 item 9: two processes refreshing one record at once leave one of
        // them holding a dead token (§4), and an in-process lock cannot stop it.
        if (store.sharedAcrossProcesses && !crossProcessLock.excludesOtherProcesses) {
            throw ProtelesException.Configuration(
                "the token store is shared with the app's other processes, so their refreshes must be serialised with this " +
                    "one's: use a cross-process lock (on Android, FileCrossProcessLock.forClient(context, clientId)), not an " +
                    "in-process one (docs/mobile-SDKs.md §10.9 item 9)",
            )
        }
    }

    /** After a 429 from any endpoint, nothing more until its wait has passed (§10.9 item 3). */
    private val rateLimits = RateLimitGate(clock)
    private val tokens = TokenClient(transport, configuration.clientId, clock, rateLimits)
    private val verifier = IdTokenVerifier(clock)

    /** Taken before the cross-process lock: refreshes are single-flight in the process (§10.3). */
    private val sessionMutex = Mutex()
    private val discoveryMutex = Mutex()

    /** A sign-in or end-session is showing the browser: there is one at a time (§10.9 item 8). */
    private val browserFlow = AtomicBoolean(false)

    @Volatile private var metadata: ProviderMetadata? = null

    @Volatile private var keys: JwksCache? = null

    /**
     * Refresh tokens this client has seen refused (`invalid_grant`), revoked or
     * abandoned. A stored session holding one is dead (§10.9 item 1): it reads as
     * signed out, a refresh clears it rather than present the token, and so a
     * dead token is never presented to the token endpoint twice (§4, trap 9) —
     * even when the store could not be cleared at the time. Sign-out still
     * revokes it (see takeSession).
     */
    private val retired: MutableSet<String> = ConcurrentHashMap.newKeySet()

    /**
     * After a refresh failed while the stored access token was still valid: no
     * new attempt before this instant (epoch seconds), so every API call during a
     * server outage does not become a token request (§10.9 item 3).
     */
    @Volatile private var refreshRetryAt: Long = Long.MIN_VALUE

    /**
     * The issuer's discovery document (§10.2 step 1): fetched once, its `issuer`
     * held to the configured one byte for byte, then cached for the life of this
     * instance. A failure is not cached.
     */
    public suspend fun providerMetadata(): ProviderMetadata {
        metadata?.let { return it }
        return discoveryMutex.withLock {
            metadata ?: discover().also {
                keys = JwksCache(it.jwksUri, transport, clock, rateLimits = rateLimits)
                metadata = it
            }
        }
    }

    /**
     * Signs the user in (§10.2): discovery, PKCE, the browser hop, the callback
     * checks, the code exchange, ID-token verification with this login's nonce and
     * access token — and the session is **persisted before this returns**.
     *
     * Cancelling the caller cancels the browser hop, but not what follows it:
     * once the browser has returned a code, the exchange, verification and save
     * run to completion (bounded by the transport's timeouts), so a screen
     * recreated meanwhile finds the user signed in. Call it from a scope that
     * survives configuration changes (`viewModelScope`, an application scope),
     * not one a rotation cancels while the user is in the browser.
     *
     * Tokens the server issued but this client will not hold — the ID token was
     * refused, the response was malformed, the session could not be saved or
     * the lock could not be taken to save it — are revoked, not left alive for
     * thirty days (§10.9 item 7).
     *
     * @throws ProtelesException.Cancelled when the user dismisses the browser.
     * @throws ProtelesException.AlreadyInProgress while another sign-in or
     *   end-session of this client is showing the browser (§10.9 item 8).
     * @throws ProtelesException.RateLimited before the browser opens, while a 429's
     *   `Retry-After` has not passed: the code could not be redeemed anyway.
     */
    public suspend fun signIn(browser: BrowserHop): IdTokenClaims {
        if (!browserFlow.compareAndSet(false, true)) throw ProtelesException.AlreadyInProgress()
        try {
            rateLimits.remaining()?.let { throw ProtelesException.RateLimited(it) }
            val md = providerMetadata()
            val request = AuthorizationRequest.create(md, configuration, random)
            val callback = browser.open(request.url, request.redirectUri)
            val code = AuthorizationCallback.parse(callback, request.redirectUri, request.state, configuration.issuer)
            // The user has authenticated and the code is single-use; once the server
            // answers, a refresh-token family exists that only this code can persist
            // or revoke. So from here nothing is abandoned half-way.
            return withContext(NonCancellable) { redeem(md, request, code) }
        } finally {
            browserFlow.set(false)
        }
    }

    /** Called under NonCancellable. */
    private suspend fun redeem(md: ProviderMetadata, request: AuthorizationRequest, code: String): IdTokenClaims {
        // The refresh token the server issued, as soon as a 200 body names it:
        // whatever fails after that — the rest of the response, the ID token, the
        // store, the lock — it is revoked rather than left to nobody.
        var issued: String? = null
        try {
            // The lifetime starts before the request is sent, as a refresh's does:
            // the server's clock started it at some moment after this one, so the
            // token is never counted valid for longer than it is.
            val requestedAt = clock.epochSeconds()
            val response = tokens.exchangeCode(md.tokenEndpoint, code, request.redirectUri, request.codeVerifier) { issued = it }
            val idToken = response.idToken
                ?: throw ProtelesException.IdTokenRejected(IdTokenRejection.MISSING, "the token response carried no id_token")
            val claims = verifier.verify(
                idToken,
                keySource(),
                IdTokenExpectation(configuration.issuer, configuration.clientId, request.nonce, response.accessToken),
            )
            val session = StoredSession(
                issuer = configuration.issuer,
                clientId = configuration.clientId,
                accessToken = response.accessToken,
                obtainedAt = requestedAt,
                expiresAt = saturatingAdd(requestedAt, response.expiresIn),
                refreshToken = response.refreshToken,
                idToken = response.idToken,
                claims = claims,
                scope = response.scope,
            )
            try {
                exclusive { writeStore(session) }
            } catch (e: LockUnavailable) {
                // §10.9 item 7: saved without the lock, a refresh another process is
                // running could write its rotation over this sign-in.
                throw e.error
            }
            refreshRetryAt = Long.MIN_VALUE
            return claims
        } catch (e: Exception) {
            issued?.let { revokeQuietly(it) }
            throw e
        }
    }

    /**
     * The stored access token, refreshed first when it is past half its life
     * (§10.3, §4 "refresh early").
     *
     * The refresh is single-flight in this process and serialised across processes;
     * after taking the lock the store is **re-read**, so a refresh another
     * coroutine or process already made is used rather than repeated. The rotated
     * refresh token is persisted before the new access token is returned. When
     * the lock cannot be taken in time, the store is re-read anyway and a stored
     * token that has not expired is returned (§10.9 item 9).
     *
     * A refresh that fails for any reason but the three below, while the stored
     * token has not yet expired, returns the stored token and raises nothing
     * (§10.3 and §10.9 item 1); the next attempt waits up to
     * [REFRESH_RETRY_SECONDS] — never more than half the time the token has left
     * — or, after a 429, `Retry-After` (§10.9 item 3). The failure is raised once
     * the stored token has expired. Three failures end the session at once — the
     * store is cleared and the failure raised: `invalid_grant`, a refresh-minted
     * ID token that fails a trust rule, and a refresh token this client already
     * knows is dead. A store that cannot be written is raised at once too, but
     * does not end the session.
     *
     * @throws ProtelesException.SignInRequired nobody is signed in, or the session
     *   has ended (`invalid_grant`, or a refresh token known to be dead; the store
     *   is cleared; never retried).
     * @throws ProtelesException.IdTokenRejected a refresh-minted ID token failed a
     *   trust rule: the session is cleared and its refresh token revoked.
     * @throws ProtelesException.Storage the store could not be read or written.
     * @throws ProtelesException.RateLimited HTTP 429, once the stored token has
     *   expired. Until its wait passes no request is sent.
     */
    public suspend fun validAccessToken(): String {
        val seen = readStored() ?: throw ProtelesException.SignInRequired("nobody is signed in")
        if (!isDead(seen) && !refreshDue(seen)) return seen.accessToken
        return try {
            exclusive {
                val current = readStored() ?: throw ProtelesException.SignInRequired("nobody is signed in")
                when {
                    isDead(current) -> endDeadSession()
                    !refreshDue(current) -> current.accessToken
                    else -> refresh(current)
                }
            }
        } catch (e: LockUnavailable) {
            // Another process has held the lock past the wait, most likely while
            // refreshing: what it wrote may be usable (§10.9 item 9).
            val again = readStore() ?: throw ProtelesException.SignInRequired("nobody is signed in")
            if (unexpired(again)) again.accessToken else throw e.error
        }
    }

    /**
     * The claims of the signed-in user's last verified ID token, or null when nobody
     * is signed in. Valid for the session, not for the ID token's own 15 minutes
     * (trap 7).
     */
    public suspend fun currentClaims(): IdTokenClaims? = readStore()?.claims

    /** Whether a session is stored. It may still turn out to need a sign-in when refreshed. */
    public suspend fun isSignedIn(): Boolean = readStore() != null

    /**
     * Signs out (§10.4, §10.9 item 6): **clears the store, then revokes** the
     * refresh token at the revocation endpoint — the revocation is attempted
     * whether or not the store could be cleared, and the store is cleared
     * whether or not the revocation succeeds: a device that cannot reach the
     * server can still sign out locally, and the revocation's outcome is
     * reported rather than hidden. A record that is there but cannot be read is
     * still deleted, and reported as a failed revocation, not as nothing to
     * revoke. A stored refresh token this client already knows is dead is
     * revoked too: an earlier revocation of it may have failed.
     *
     * Neither half can be cancelled by the caller: once asked, the device signs
     * out even if the caller is cancelled while it waits for the lock or the
     * server (the lock's wait and the transport's timeouts bound it). When the
     * lock cannot be taken in time the store is cleared without it (§10.9 item 9).
     *
     * With [endSession], the browser is then sent to the end-session endpoint with
     * `id_token_hint`, `client_id`, `post_logout_redirect_uri` and `state`, to end
     * the browser session too. Without it the browser stays signed in and the next
     * sign-in is silent. Pass it only from a user gesture.
     *
     * @throws ProtelesException.AlreadyInProgress — having done nothing — when
     *   [endSession] is passed while a sign-in or end-session of this client is
     *   showing the browser (§10.9 item 8). Without it, sign-out proceeds.
     * @throws ProtelesException.Storage when the store could not be cleared —
     *   after the refresh token was revoked, or the revocation failed (then its
     *   error is suppressed into this one).
     */
    public suspend fun signOut(endSession: BrowserHop? = null): SignOutResult {
        if (endSession == null) return signOutLocally(null)
        if (!browserFlow.compareAndSet(false, true)) throw ProtelesException.AlreadyInProgress()
        try {
            return signOutLocally(endSession)
        } finally {
            browserFlow.set(false)
        }
    }

    /** [signOut], with [browserFlow] already held when [endSession] is passed. */
    private suspend fun signOutLocally(endSession: BrowserHop?): SignOutResult {
        val (taken, revocation) = withContext(NonCancellable) {
            val taken = try {
                exclusive { takeSession() }
            } catch (e: LockUnavailable) {
                // A device must always be able to sign out. A refresh another process
                // is running checks the record before it writes, and finds it gone.
                takeSession()
            }
            // The network only now, with the session already gone from this device —
            // or, if it could not be cleared, revoked anyway: the person asked to
            // sign out, and a revoked token in a stale store fails safe.
            val revocation = taken.unrevocable?.let { SignOutResult.Revocation.Failed(it) } ?: revoke(taken.refreshToken)
            taken to revocation
        }
        taken.clearFailure?.let { failure ->
            (revocation as? SignOutResult.Revocation.Failed)?.let { failure.addSuppressed(it.error) }
            throw failure
        }
        val ended = endSession?.let { endBrowserSession(it, taken.idToken) }
        return SignOutResult(revocation, ended)
    }

    // --- internals ----------------------------------------------------------

    private suspend fun discover(): ProviderMetadata {
        val url = ProviderMetadata.discoveryUrl(configuration.issuer)
        val response = sendOrNetworkError(transport, HttpRequest("GET", url, mapOf("Accept" to "application/json")))
        when (response.status) {
            200 -> Unit
            429 -> throw rateLimits.close(response)
            in 400..499 -> throw ProtelesException.Configuration(
                "discovery at $url answered HTTP ${response.status}: is the issuer right?",
            )
            else -> throw ProtelesException.Network("discovery at $url answered HTTP ${response.status}", httpStatus = response.status)
        }
        val document = try {
            Json.parseObjectUtf8(response.body)
        } catch (e: JsonSyntaxException) {
            throw ProtelesException.Configuration("the discovery document at $url is not a JSON object")
        }
        return ProviderMetadata.parse(document, configuration.issuer)
    }

    private suspend fun keySource(): KeySource {
        providerMetadata()
        return keys!!
    }

    /** Whether [validAccessToken] should try a refresh now. */
    private fun refreshDue(session: StoredSession): Boolean {
        if (!pastHalfLife(session)) return false
        // After a failed refresh or a 429, a token that is still valid is used
        // rather than asking again before the back-off or Retry-After has passed.
        val holdingOff = clock.epochSeconds() < refreshRetryAt || rateLimits.remaining() != null
        return !(holdingOff && unexpired(session))
    }

    private fun pastHalfLife(session: StoredSession): Boolean {
        val now = clock.epochSeconds()
        // A clock that went back past the moment the token was obtained says
        // nothing trustworthy about its age: refresh. (The refresh-minted ID
        // token's exp and iat are not held to this clock, so this cannot end the
        // session — §10.9 item 2.)
        if (now < session.obtainedAt - IdTokenVerifier.CLOCK_SKEW_SECONDS) return true
        return now >= session.obtainedAt + (session.expiresAt - session.obtainedAt) / 2
    }

    private fun unexpired(session: StoredSession): Boolean = clock.epochSeconds() < session.expiresAt

    /** Whether [session]'s refresh token is one this client knows is dead. */
    private fun isDead(session: StoredSession): Boolean = session.refreshToken?.let { it in retired } == true

    /**
     * §10.9 item 1: a stored session whose refresh token is known dead ends — it
     * is cleared rather than presented again. Called under the lock.
     */
    private suspend fun endDeadSession(): Nothing {
        val ended = ProtelesException.SignInRequired("this session's refresh token was refused or revoked earlier; sign in again")
        try {
            clearStore()
        } catch (e: ProtelesException.Storage) {
            ended.addSuppressed(e)
        }
        throw ended
    }

    /** Called with the session mutex and the cross-process lock held. */
    private suspend fun refresh(current: StoredSession): String {
        val now = clock.epochSeconds()
        val refreshToken = current.refreshToken
        if (refreshToken == null) {
            // The client was not registered for the refresh_token grant (trap 4).
            if (now < current.expiresAt) return current.accessToken
            clearStore()
            throw ProtelesException.SignInRequired("the access token has expired and there is no refresh token")
        }
        return try {
            // After a 429, nothing — discovery included — before its wait has passed.
            rateLimits.remaining()?.let { throw ProtelesException.RateLimited(it) }
            val md = providerMetadata()
            // From here the refresh finishes even if the caller is cancelled (a screen
            // closed, a scope torn down): the server rotates the moment it answers, so
            // a response abandoned in flight is a signed-out user (§2.3, §4). The
            // transport's timeouts bound how long this can take.
            withContext(NonCancellable) { rotate(current, refreshToken, md, now) }
        } catch (e: ProtelesException) {
            // §10.3 and §10.9 item 1: any other failure, while the stored token is
            // still valid, returns it — refreshing at half-life exists so that
            // expiry is a non-event — and holds the next attempt off (item 3).
            if (!recoverable(e) || now >= current.expiresAt) throw e
            refreshRetryAt = now + minOf(REFRESH_RETRY_SECONDS, maxOf(1L, (current.expiresAt - now) / 2))
            current.accessToken
        }
    }

    /**
     * Whether a refresh failure can wait for the stored token to expire (§10.9
     * item 1). Not `invalid_grant` or a dead refresh token (the session is over),
     * not an ID token that failed a trust rule (the session was abandoned), and
     * not a store that cannot be written (a local fault the caller must hear
     * about — though the session stands).
     */
    private fun recoverable(e: ProtelesException): Boolean = when (e) {
        is ProtelesException.SignInRequired, is ProtelesException.IdTokenRejected, is ProtelesException.Storage -> false
        else -> true
    }

    /** Called under NonCancellable, with the session mutex and the cross-process lock held. */
    private suspend fun rotate(current: StoredSession, refreshToken: String, md: ProviderMetadata, now: Long): String {
        var rotated = current
        val response = try {
            tokens.refresh(md.tokenEndpoint, refreshToken) { next ->
                // Rotation is single-use and has already happened server-side: the
                // new refresh token is now the only live credential, so it is
                // persisted before the rest of the response is even checked — and
                // before the new access token is returned (§10.9 item 5).
                rotated = current.copy(refreshToken = next)
                checkStillHeld(refreshToken, live = next)
                writeStore(rotated)
            }
        } catch (e: ProtelesException.TokenEndpointError) {
            if (e.error == "invalid_grant") {
                // Terminal (§4): retrying costs rate-limit budget, and a retry
                // more than 60 s after the rotation reads as theft: it burns
                // what the family still holds and files refresh_token.reuse
                // against the tenant.
                val ended = ProtelesException.SignInRequired("the session has ended; sign in again", e)
                retire(current, ended)
                throw ended
            }
            throw e
        }

        val claims = response.idToken?.let { refreshedClaims(it, response.accessToken, current, rotated) }
        val next = rotated.copy(
            accessToken = response.accessToken,
            obtainedAt = now,
            expiresAt = saturatingAdd(now, response.expiresIn),
            idToken = if (claims != null) response.idToken else current.idToken,
            claims = claims ?: current.claims,
            scope = response.scope ?: current.scope,
        )
        rotated.refreshToken?.let { checkStillHeld(it, live = it) }
        writeStore(next)
        refreshRetryAt = Long.MIN_VALUE
        return next.accessToken
    }

    /**
     * Before a refresh writes: the record must still hold [expected], the token
     * this refresh started from. A sign-out that could not take the lock clears
     * it without the lock (§10.9 item 9), and that sign-out stands: [live], the
     * token this refresh now holds, is revoked rather than written back over it.
     * A record that cannot be read now could be read a moment ago: the write goes
     * ahead and reports whatever is wrong.
     */
    private suspend fun checkStillHeld(expected: String, live: String) {
        val record = try {
            readStored()
        } catch (e: ProtelesException.Storage) {
            return
        }
        if (record?.refreshToken == expected) return
        retired.add(live)
        revokeQuietly(live)
        if (record == null) throw ProtelesException.SignInRequired("signed out while this refresh was in flight")
        throw ProtelesException.Network("the stored session was replaced while this refresh was in flight; retry")
    }

    /**
     * The claims of a refresh-minted ID token to adopt, or null to keep the
     * previous ones. It is verified with the explicit null nonce and the new
     * access token's `at_hash`, and must name the stored `sub` (OIDC Core
     * §12.2). A trust failure — signature, key, `iss`, `aud`, `at_hash`, a
     * changed `sub`, or any other rule it breaks — abandons the session
     * (§10.9 item 1). Two things do not, because they say nothing against a
     * token the token endpoint just handed this client over TLS for its own
     * refresh token:
     *
     * - its `exp` and `iat` disagreeing with this device's clock (§10.9 item 2:
     *   set back by hand, an RTC reset): `at_hash` already binds it to the
     *   access token minted with it. It is not adopted — its times cannot be
     *   checked here — but the session goes on (the iOS SDK does the same);
     * - a key set that cannot be fetched now: the new tokens are kept with the
     *   previous claims, rather than dropped and rotated again on the next call.
     */
    private suspend fun refreshedClaims(
        idToken: String,
        accessToken: String,
        current: StoredSession,
        rotated: StoredSession,
    ): IdTokenClaims? {
        val verified = try {
            verifier.verify(
                idToken,
                keySource(),
                // The refresh grant mints no nonce: null is the explicit skip (§5.2 divergence 4).
                IdTokenExpectation(configuration.issuer, configuration.clientId, nonce = null, accessToken = accessToken, checkTime = false),
            )
        } catch (e: ProtelesException.IdTokenRejected) {
            abandon(rotated, e)
            throw e
        } catch (e: ProtelesException) {
            return null
        }
        val previous = current.claims?.subject
        if (previous != null && verified.subject != previous) {
            val e = ProtelesException.IdTokenRejected(
                IdTokenRejection.SUBJECT_CHANGED,
                "a refresh-minted ID token names another subject (OIDC Core §12.2)",
            )
            abandon(rotated, e)
            throw e
        }
        if (verifier.timeRejection(verified) != null) return null
        return verified
    }

    private suspend fun revoke(refreshToken: String?): SignOutResult.Revocation {
        refreshToken ?: return SignOutResult.Revocation.NothingToRevoke
        return try {
            val endpoint = providerMetadata().revocationEndpoint
                ?: throw ProtelesException.Configuration("the issuer advertises no revocation_endpoint")
            tokens.revoke(endpoint, refreshToken, "refresh_token")
            SignOutResult.Revocation.Revoked
        } catch (e: CancellationException) {
            throw e
        } catch (e: ProtelesException) {
            SignOutResult.Revocation.Failed(e)
        }
    }

    private suspend fun revokeQuietly(refreshToken: String?) {
        revoke(refreshToken)
    }

    /** Drops a session that cannot be trusted, and ends its family server-side if it can. */
    private suspend fun abandon(session: StoredSession, cause: ProtelesException) {
        retire(session, cause)
        revokeQuietly(session.refreshToken)
    }

    /**
     * Forgets [session]: its refresh token is never presented again by this
     * client, and the store is cleared. A store that cannot be cleared does not
     * replace [cause] — it is suppressed into it — and the session still reads as
     * signed out here.
     */
    private suspend fun retire(session: StoredSession, cause: ProtelesException) {
        session.refreshToken?.let { retired.add(it) }
        try {
            clearStore()
        } catch (e: ProtelesException.Storage) {
            cause.addSuppressed(e)
        }
    }

    /** What sign-out took from the store, and what went wrong taking it. */
    private class Taken(
        val refreshToken: String?,
        val idToken: String?,
        /** Why the refresh token cannot be revoked: a record was there and could not be read. */
        val unrevocable: ProtelesException?,
        /** Why the record is still there. */
        val clearFailure: ProtelesException.Storage?,
    )

    /**
     * Reads what sign-out needs, then deletes the record whatever the read found:
     * a record that cannot be read still has to go (§10.9 item 6).
     *
     * A session whose refresh token this client knows is dead is read too, and
     * its token revoked: it may be dead only here. An ID token abandoned while
     * offline was retired but its family's revocation failed, and revoking any
     * member ends the family server-side; a token the server already refused
     * is answered 200 (RFC 7009 §2.2), and revocation is not the refresh grant,
     * so it files no stale-presentation warning.
     */
    private suspend fun takeSession(): Taken {
        var unrevocable: ProtelesException? = null
        val session = try {
            readRecord()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // Whether the record holds a live refresh token is unknown: that is a
            // revocation that did not happen, not "nothing to revoke".
            unrevocable = ProtelesException.Storage("the stored session could not be read, so its refresh token could not be revoked", e)
            null
        }
        session?.refreshToken?.let { retired.add(it) }
        refreshRetryAt = Long.MIN_VALUE
        val clearFailure = try {
            clearStore()
            null
        } catch (e: ProtelesException.Storage) {
            e
        }
        return Taken(session?.refreshToken, session?.idToken, unrevocable, clearFailure)
    }

    /** Called holding [browserFlow]. */
    private suspend fun endBrowserSession(browser: BrowserHop, idTokenHint: String?): SignOutResult.EndSession {
        return try {
            val endpoint = providerMetadata().endSessionEndpoint
                ?: throw ProtelesException.Configuration("the issuer advertises no end_session_endpoint")
            val state = Pkce.randomToken(random)
            val returnUri = configuration.postLogoutRedirectUri
            val params = buildList {
                idTokenHint?.let { add("id_token_hint" to it) }
                add("client_id" to configuration.clientId)
                returnUri?.let { add("post_logout_redirect_uri" to it) }
                add("state" to state)
            }
            val returned = browser.open(AuthorizationRequest.appendQuery(endpoint, params), returnUri)
            if (returnUri != null) AuthorizationCallback.checkEndSessionReturn(returned, returnUri, state)
            SignOutResult.EndSession.Completed
        } catch (e: ProtelesException.Cancelled) {
            SignOutResult.EndSession.Dismissed
        } catch (e: CancellationException) {
            throw e
        } catch (e: ProtelesException) {
            SignOutResult.EndSession.Failed(e)
        }
    }

    /** The cross-process lock could not be taken, so the action did not run; [error] reports why. */
    private class LockUnavailable(val error: ProtelesException) : Exception(error.message, error)

    /**
     * The session mutex, then the cross-process lock. Throws [LockUnavailable] —
     * which every caller handles in its own way (§10.9 item 9) — when the lock
     * could not be taken; [action]'s own failures propagate as they are.
     */
    private suspend fun <T> exclusive(action: suspend () -> T): T = sessionMutex.withLock {
        var entered = false
        try {
            crossProcessLock.withLock {
                entered = true
                action()
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (entered) throw e as? ProtelesException ?: ProtelesException.Storage("the cross-process lock failed", e)
            // A lock wait interrupted by cancellation can surface as an IOException
            // (ClosedByInterruptException): that is the caller's cancellation.
            currentCoroutineContext().ensureActive()
            throw LockUnavailable(e as? ProtelesException ?: ProtelesException.Storage("the cross-process lock could not be taken", e))
        }
    }

    /**
     * The stored record, if it is this configuration's. Throws
     * [ProtelesException.Storage] for a read that failed, and passes
     * [UnreadableSessionException] on for a record that can never be read.
     */
    private suspend fun readRecord(): StoredSession? {
        val session = try {
            store.read()
        } catch (e: CancellationException) {
            throw e
        } catch (e: UnreadableSessionException) {
            throw e
        } catch (e: Exception) {
            throw ProtelesException.Storage("the session could not be read", e)
        }
        // A session written for another issuer or client is not this configuration's.
        return session?.takeIf { it.issuer == configuration.issuer && it.clientId == configuration.clientId }
    }

    /**
     * The stored session, dead or alive. A record that can never be read is no
     * session — it is left in place for the next sign-in or sign-out to replace
     * — while a read that failed is [ProtelesException.Storage], never "signed out".
     */
    private suspend fun readStored(): StoredSession? = try {
        readRecord()
    } catch (e: UnreadableSessionException) {
        null
    }

    /** The stored session, unless its refresh token is known dead. */
    private suspend fun readStore(): StoredSession? = readStored()?.takeUnless { isDead(it) }

    private suspend fun writeStore(session: StoredSession) {
        try {
            store.write(session)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw ProtelesException.Storage("the session could not be written", e)
        }
    }

    private suspend fun clearStore() {
        try {
            store.clear()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw ProtelesException.Storage("the session could not be cleared", e)
        }
    }

    public companion object {
        /**
         * The longest a failed refresh is held off while the stored token is still
         * valid (never more than half the time it has left; §10.9 item 3).
         */
        public const val REFRESH_RETRY_SECONDS: Long = 30
    }
}

/** What [ProtelesClient.signOut] did. The local session is gone whenever this is returned. */
public class SignOutResult internal constructor(
    public val revocation: Revocation,
    /** Null when the browser session was not asked to end. */
    public val endSession: EndSession?,
) {
    public sealed class Revocation {
        /** The refresh token is dead server-side. */
        public data object Revoked : Revocation()

        /** There was no refresh token to revoke. */
        public data object NothingToRevoke : Revocation()

        /** The server was not told; the refresh token lives until it expires, thirty days after sign-in by default. */
        public class Failed(public val error: ProtelesException) : Revocation()
    }

    public sealed class EndSession {
        /** The browser came back to the post-logout redirect URI with the state that was sent. */
        public data object Completed : EndSession()

        /** The user closed the browser; whether they confirmed the sign-out first is unknown. */
        public data object Dismissed : EndSession()

        public class Failed(public val error: ProtelesException) : EndSession()
    }

    override fun toString(): String = "SignOutResult(revocation=$revocation, endSession=$endSession)"
}
