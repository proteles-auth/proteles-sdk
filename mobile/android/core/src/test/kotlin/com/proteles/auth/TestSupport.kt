package com.proteles.auth

import java.io.IOException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

const val ISSUER = "https://auth.example.test/t/acme"
const val CLIENT_ID = "com.example.mobile"
const val REDIRECT = "https://mobile.example.com/oauth/callback"
const val POST_LOGOUT = "https://mobile.example.com/oauth/signed-out"
const val AUTHORIZE = "$ISSUER/oauth/authorize"
const val TOKEN = "$ISSUER/oauth/token"
const val JWKS = "$ISSUER/.well-known/jwks.json"
const val REVOKE = "$ISSUER/oauth/revoke"
const val END_SESSION = "$ISSUER/oauth/logout"
const val DISCOVERY = "$ISSUER/.well-known/openid-configuration"

/** Plain Kotlin values to JSON, for building fixtures. */
internal fun toJson(value: Any?): JsonValue = when (value) {
    null -> JsonNull
    is JsonValue -> value
    is String -> JsonString(value)
    is Boolean -> JsonBoolean(value)
    is Int, is Long -> JsonNumber(value.toString())
    is Double -> JsonNumber(value.toString())
    is Map<*, *> -> JsonObject(value.entries.associate { (k, v) -> k as String to toJson(v) })
    is List<*> -> JsonArray(value.map { toJson(it) })
    else -> error("no JSON for ${value::class}")
}

fun jsonText(value: Any?): String = Json.write(toJson(value))

class MutableClock(start: Long) : Clock {
    private val now = AtomicLong(start)
    override fun epochSeconds(): Long = now.get()
    fun set(t: Long) = now.set(t)
    fun advance(seconds: Long) = now.addAndGet(seconds)
}

fun ok(json: Any?, headers: Map<String, List<String>> = emptyMap()) =
    HttpResponse(200, headers + ("Content-Type" to listOf("application/json")), jsonText(json).toByteArray())

fun status(code: Int, json: Any? = null, headers: Map<String, List<String>> = emptyMap()) =
    HttpResponse(code, headers, if (json == null) ByteArray(0) else jsonText(json).toByteArray())

/**
 * A scripted server: each request is matched by method and URL (query ignored)
 * to a handler, and every request is recorded.
 */
class StubTransport : Transport {
    val requests: MutableList<HttpRequest> = CopyOnWriteArrayList()
    private val routes = LinkedHashMap<String, suspend (HttpRequest) -> HttpResponse>()

    fun on(method: String, url: String, handler: suspend (HttpRequest) -> HttpResponse): StubTransport {
        routes["$method $url"] = handler
        return this
    }

    fun requestsTo(url: String): List<HttpRequest> = requests.filter { it.url.substringBefore('?') == url }

    override suspend fun send(request: HttpRequest): HttpResponse {
        requests.add(request)
        val handler = routes["${request.method} ${request.url.substringBefore('?')}"]
            ?: throw IOException("no route for ${request.method} ${request.url}")
        return handler(request)
    }
}

/** A form body as name → values. */
fun HttpRequest.form(): Map<String, List<String>> =
    PercentEncoding.decodeQuery(bodyText.orEmpty()).groupBy({ it.first }, { it.second })

fun HttpRequest.formValue(name: String): String? = form()[name]?.single()

fun queryOf(url: String): Map<String, List<String>> =
    PercentEncoding.decodeQuery(url.substringAfter('?', "")).groupBy({ it.first }, { it.second })

/** An RSA key the tests sign ID tokens with, and its JWK. */
class SigningKey(val kid: String = "test-key-1", bits: Int = 2048) {
    val pair: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()

    val jwk: Map<String, Any?>
        get() {
            val pub = pair.public as RSAPublicKey
            return mapOf(
                "kty" to "RSA",
                "kid" to kid,
                "use" to "sig",
                "alg" to "RS256",
                "n" to Base64Url.encode(unsigned(pub.modulus.toByteArray())),
                "e" to Base64Url.encode(unsigned(pub.publicExponent.toByteArray())),
            )
        }

    fun sign(claims: Map<String, Any?>, header: Map<String, Any?> = mapOf("alg" to "RS256", "typ" to "JWT", "kid" to kid)): String {
        val input = Base64Url.encode(jsonText(header).toByteArray()) + "." + Base64Url.encode(jsonText(claims).toByteArray())
        val sig = Signature.getInstance("SHA256withRSA").apply {
            initSign(pair.private)
            update(input.toByteArray())
        }.sign()
        return input + "." + Base64Url.encode(sig)
    }

    private fun unsigned(b: ByteArray) = if (b.size > 1 && b[0] == 0.toByte()) b.copyOfRange(1, b.size) else b
}

val SHARED_KEY: SigningKey by lazy { SigningKey() }

fun jwksOf(vararg keys: SigningKey): Map<String, Any?> = mapOf("keys" to keys.map { it.jwk })

fun discoveryDocument(
    issuer: String = ISSUER,
    endSession: Boolean = true,
    revocation: Boolean = true,
): Map<String, Any?> = buildMap {
    put("issuer", issuer)
    put("authorization_endpoint", AUTHORIZE)
    put("token_endpoint", TOKEN)
    put("jwks_uri", JWKS)
    if (revocation) put("revocation_endpoint", REVOKE)
    if (endSession) put("end_session_endpoint", END_SESSION)
    put("code_challenge_methods_supported", listOf("S256"))
    put("authorization_response_iss_parameter_supported", true)
}

fun idTokenClaims(
    now: Long,
    nonce: String? = null,
    accessToken: String? = null,
    sub: String = "user-1",
    extra: Map<String, Any?> = emptyMap(),
): Map<String, Any?> = buildMap {
    put("iss", ISSUER)
    put("sub", sub)
    put("aud", CLIENT_ID)
    put("exp", now + 900)
    put("iat", now)
    put("auth_time", now - 5)
    nonce?.let { put("nonce", it) }
    accessToken?.let { put("at_hash", IdTokenVerifier.atHash(it)) }
    putAll(extra)
}

/** A browser that answers with whatever [respond] builds from the URL it was asked to open. */
class FakeBrowser(private val respond: suspend (url: String, returnUri: String?) -> String) : BrowserHop {
    val opened: MutableList<String> = CopyOnWriteArrayList()

    override suspend fun open(url: String, returnUri: String?): String {
        opened.add(url)
        return respond(url, returnUri)
    }
}

/** A TokenStore that records every write and can be told to fail. */
class RecordingStore : TokenStore {
    @Volatile var session: StoredSession? = null
    val writes: MutableList<StoredSession> = CopyOnWriteArrayList()
    @Volatile var clears = 0
    @Volatile var failWrites = false
    @Volatile var failClears = false
    @Volatile var failReads = false

    /** A record is there but can never be read: its key is gone, or it is another format. */
    @Volatile var unreadable = false

    override suspend fun read(): StoredSession? {
        if (failReads) throw IOException("unreadable")
        if (unreadable) throw UnreadableSessionException("sealed under a key that is gone")
        return session
    }

    override suspend fun write(session: StoredSession) {
        if (failWrites) throw IOException("disk full")
        writes.add(session)
        this.session = session
        unreadable = false
    }

    override suspend fun clear() {
        if (failClears) throw IOException("read-only")
        clears++
        session = null
        unreadable = false
    }
}

/**
 * A lock that cannot be taken — another process has held it past the wait
 * (§10.9 item 9). [whileWaiting] runs first: what that other process did
 * meanwhile. The action never runs.
 */
class UnavailableLock(
    private val error: Exception = ProtelesException.Network("timed out after 60 s waiting for another process's refresh"),
    private val whileWaiting: suspend () -> Unit = {},
) : CrossProcessLock {
    @Volatile var attempts = 0

    override suspend fun <T> withLock(action: suspend () -> T): T {
        attempts++
        whileWaiting()
        throw error
    }
}

/** A lock that excludes nothing: the failure a shared lock exists to prevent, for positive controls. */
object NoLock : CrossProcessLock {
    override suspend fun <T> withLock(action: suspend () -> T): T = action()
}

/**
 * A lock another process is holding until [release] completes. The wait does
 * not end on cancellation by itself — like `FileChannel.lock` under the
 * client's NonCancellable — only a cancellable caller would stop waiting.
 */
class HeldLock : CrossProcessLock {
    @Volatile var held = false
    val waiting = kotlinx.coroutines.CompletableDeferred<Unit>()
    val release = kotlinx.coroutines.CompletableDeferred<Unit>()

    override suspend fun <T> withLock(action: suspend () -> T): T {
        if (held) {
            waiting.complete(Unit)
            release.await()
        }
        return action()
    }
}
