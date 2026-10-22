package com.proteles.auth

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap

/**
 * A signed-in session as it is persisted: the token set and the claims of the
 * last verified ID token.
 */
public class StoredSession internal constructor(
    internal val issuer: String,
    internal val clientId: String,
    internal val accessToken: String,
    /** When the access token was obtained, in epoch seconds (local clock). */
    internal val obtainedAt: Long,
    /** obtainedAt + expires_in. */
    internal val expiresAt: Long,
    internal val refreshToken: String?,
    internal val idToken: String?,
    internal val claims: IdTokenClaims?,
    internal val scope: String?,
) {
    internal fun copy(
        accessToken: String = this.accessToken,
        obtainedAt: Long = this.obtainedAt,
        expiresAt: Long = this.expiresAt,
        refreshToken: String? = this.refreshToken,
        idToken: String? = this.idToken,
        claims: IdTokenClaims? = this.claims,
        scope: String? = this.scope,
    ): StoredSession = StoredSession(issuer, clientId, accessToken, obtainedAt, expiresAt, refreshToken, idToken, claims, scope)

    /** The subject of the session, for diagnostics. */
    public val subject: String? get() = claims?.subject

    /** The session as UTF-8 JSON, for a [TokenStore] to seal. It contains live tokens: never write it anywhere unencrypted. */
    public fun encode(): ByteArray {
        val members = LinkedHashMap<String, JsonValue>()
        members["v"] = JsonNumber(FORMAT_VERSION.toString())
        members["issuer"] = JsonString(issuer)
        members["clientId"] = JsonString(clientId)
        members["accessToken"] = JsonString(accessToken)
        members["obtainedAt"] = JsonNumber(obtainedAt.toString())
        members["expiresAt"] = JsonNumber(expiresAt.toString())
        refreshToken?.let { members["refreshToken"] = JsonString(it) }
        idToken?.let { members["idToken"] = JsonString(it) }
        claims?.let { members["claims"] = JsonString(it.payloadJson) }
        scope?.let { members["scope"] = JsonString(it) }
        return Json.write(JsonObject(members)).toByteArray(Charsets.UTF_8)
    }

    override fun toString(): String = "StoredSession(sub=$subject, expiresAt=$expiresAt, refreshable=${refreshToken != null})"

    public companion object {
        private const val FORMAT_VERSION = 1

        /** The inverse of [encode]. Throws [IllegalArgumentException] for anything [encode] would not have written. */
        public fun decode(bytes: ByteArray): StoredSession {
            val o = try {
                Json.parseObjectUtf8(bytes)
            } catch (e: JsonSyntaxException) {
                throw IllegalArgumentException("stored session is not JSON", e)
            }
            require(o.number("v")?.longOrNull() == FORMAT_VERSION.toLong()) { "unknown stored-session format" }
            fun str(name: String) = requireNotNull(o.string(name)) { "stored session has no $name" }
            fun long(name: String) = requireNotNull(o.number(name)?.longOrNull()) { "stored session has no $name" }
            val claims = o.string("claims")?.let {
                try {
                    IdTokenClaims.fromPayloadJson(it)
                } catch (e: JsonSyntaxException) {
                    throw IllegalArgumentException("stored claims are not JSON", e)
                }
            }
            return StoredSession(
                issuer = str("issuer"),
                clientId = str("clientId"),
                accessToken = str("accessToken"),
                obtainedAt = long("obtainedAt"),
                expiresAt = long("expiresAt"),
                refreshToken = o.string("refreshToken"),
                idToken = o.string("idToken"),
                claims = claims,
                scope = o.string("scope"),
            )
        }
    }
}

/**
 * Where the session lives between launches (docs/mobile-SDKs.md §10.5). On
 * Android, `KeystoreTokenStore` in the `android` module: AES-256-GCM under a key
 * that never leaves the Android Keystore. Never `SharedPreferences`, never a
 * plaintext file.
 *
 * [write] must be atomic — a reader sees the old session or the new one, never
 * a torn write — because [read] is called without the cross-process lock.
 * Implementations throw anything on failure; the client reports it as
 * [ProtelesException.Storage] and never reads it as "signed out" (§10.7).
 */
public interface TokenStore {
    /**
     * The stored session, or null when nothing is stored. Throws
     * [UnreadableSessionException] when a record is there but can never be
     * read (its key is gone, it was tampered with, it is another format): the
     * client treats that as no session, and sign-out still deletes it and
     * reports that its refresh token could not be revoked (§10.9 item 6).
     */
    public suspend fun read(): StoredSession?

    public suspend fun write(session: StoredSession)

    public suspend fun clear()

    /**
     * Whether other processes of the app read and write this same record — true
     * for `KeystoreTokenStore`, whose file every process of the app can reach.
     * A shared store needs a [CrossProcessLock] that excludes those processes,
     * and [ProtelesClient] refuses one with only an in-process lock
     * (§10.9 item 9). Override it for a store of your own that is shared.
     */
    public val sharedAcrossProcesses: Boolean get() = false
}

/**
 * Thrown by [TokenStore.read] when a record is present but can never be read
 * — as opposed to a read that failed and may succeed later, which is any other
 * exception and is reported as [ProtelesException.Storage].
 */
public class UnreadableSessionException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** A [TokenStore] in memory: for tests, and for apps that want no persistence at all. */
public class InMemoryTokenStore : TokenStore {
    @Volatile private var session: StoredSession? = null

    override suspend fun read(): StoredSession? = session

    override suspend fun write(session: StoredSession) {
        this.session = session
    }

    override suspend fun clear() {
        session = null
    }
}

/**
 * Serialises refreshes across the processes of one app (docs/mobile-SDKs.md
 * §10.6) — an app and its background worker share one token record, and two
 * concurrent refreshes leave one of them holding a dead token. On Android,
 * `FileCrossProcessLock.forClient(context, clientId)` in the `android` module
 * (`FileChannel.lock`), which `ProtelesAndroid.client` already uses.
 *
 * It must exclude **every** holder of the same token record: other processes,
 * and other [ProtelesClient] instances in this process — each client's own
 * mutex covers only itself. The client takes that mutex first, so one client
 * never asks an implementation to lock twice.
 */
public interface CrossProcessLock {
    /**
     * Runs [action] holding the lock. Throws without running it when the lock
     * cannot be taken — in time, or at all — and the client then goes on without
     * it where it safely can (§10.9 item 9): sign-out still clears, a refresh
     * re-reads the store and returns a usable token if there is one, and a
     * sign-in revokes what it got. A [ProtelesException] thrown here is reported
     * as it is; anything else as [ProtelesException.Storage].
     */
    public suspend fun <T> withLock(action: suspend () -> T): T

    /**
     * Whether this lock excludes other processes, not only this one. A
     * [TokenStore] that is [shared across processes][TokenStore.sharedAcrossProcesses]
     * with a lock that does not is refused at construction (§10.9 item 9).
     */
    public val excludesOtherProcesses: Boolean get() = true

    public companion object {
        private val inProcessGates = ConcurrentHashMap<String, Mutex>()

        /**
         * A lock shared by every caller in **this process** that passes the same
         * [key] — use one key per token record, e.g. the client id. It excludes
         * nothing in another process: use it only when no other process of the
         * app ever builds a client for the same record (on Android, use
         * `FileCrossProcessLock` instead).
         */
        @JvmStatic
        public fun inProcessOnly(key: String): CrossProcessLock {
            val gate = inProcessGates.getOrPut(key) { Mutex() }
            return object : CrossProcessLock {
                override suspend fun <T> withLock(action: suspend () -> T): T = gate.withLock { action() }

                override val excludesOtherProcesses: Boolean get() = false
            }
        }
    }
}

/**
 * The system browser (docs/mobile-SDKs.md §10.2 step 3) — a Custom Tab on
 * Android, `ASWebAuthenticationSession` on iOS; never a WebView.
 */
public interface BrowserHop {
    /**
     * Shows [url] and suspends until the browser is sent to [returnUri], returning
     * the whole URI it was sent to. Throws [ProtelesException.Cancelled] when the
     * user dismisses the browser first. [returnUri] is null when nothing will come
     * back (ending a browser session with no post-logout redirect registered):
     * then dismissal is the only ending.
     */
    public suspend fun open(url: String, returnUri: String?): String
}
