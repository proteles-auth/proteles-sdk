package com.proteles.auth.live

import com.proteles.auth.Clock
import com.proteles.auth.HttpRequest
import com.proteles.auth.HttpResponse
import com.proteles.auth.HttpUrlConnectionTransport
import com.proteles.auth.StoredSession
import com.proteles.auth.TokenStore
import com.proteles.auth.Transport
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpResponse.BodyHandlers
import java.security.MessageDigest
import java.time.Duration
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.net.http.HttpRequest as JdkHttpRequest

/** What mobile/live/run-live.sh hands a test (its README, "What a test gets"). */
class LiveServer private constructor(
    val issuer: String,
    val clientId: String,
    val redirectUri: String,
    val postLogoutRedirectUri: String,
    val username: String,
    val password: String,
) {
    companion object {
        fun fromEnvironment(): LiveServer {
            fun env(name: String): String = System.getenv(name)?.takeIf { it.isNotEmpty() }
                ?: throw IllegalStateException("$name is unset: run this under mobile/live/run-live.sh")
            return LiveServer(
                issuer = env("PROTELES_LIVE_ISSUER"),
                clientId = env("PROTELES_LIVE_CLIENT_ID"),
                redirectUri = env("PROTELES_LIVE_REDIRECT_URI"),
                postLogoutRedirectUri = env("PROTELES_LIVE_POST_LOGOUT_REDIRECT_URI"),
                username = env("PROTELES_LIVE_USERNAME"),
                password = env("PROTELES_LIVE_PASSWORD"),
            )
        }
    }
}

/** The system clock plus an offset a test moves: how a test gets past half-life without waiting 7m30s. */
class OffsetClock : Clock {
    @Volatile var offsetSeconds: Long = 0

    override fun epochSeconds(): Long = System.currentTimeMillis() / 1000 + offsetSeconds
}

/**
 * The SDK's own transport ([HttpUrlConnectionTransport], its default), with every
 * exchange recorded as the server sent it. [tamper] rewrites a response after it
 * is recorded, before the SDK sees it: the negative controls, which show the
 * SDK's checks are what accepted the real server's answers.
 */
class RecordingTransport(private val inner: Transport = HttpUrlConnectionTransport()) : Transport {
    class Exchange(val request: HttpRequest, val response: HttpResponse) {
        val form: Map<String, String> get() = formOf(request.bodyText.orEmpty())
        val body: String get() = response.body.toString(Charsets.UTF_8)
        override fun toString(): String = "${request.method} ${request.url.substringBefore('?')} → ${response.status}"
    }

    val exchanges: MutableList<Exchange> = CopyOnWriteArrayList()

    @Volatile var tamper: ((HttpRequest, HttpResponse) -> HttpResponse)? = null

    override suspend fun send(request: HttpRequest): HttpResponse {
        val response = inner.send(request)
        exchanges += Exchange(request, response)
        return tamper?.invoke(request, response) ?: response
    }

    fun to(url: String): List<Exchange> = exchanges.filter { it.request.url.substringBefore('?') == url }

    fun tokenRequests(tokenEndpoint: String, grant: String): List<Exchange> = to(tokenEndpoint).filter { it.form["grant_type"] == grant }
}

/**
 * A [TokenStore] in memory that can be shared by two clients, as two clients of
 * one app share one record. The record is kept encoded — as a real store keeps
 * it — so what a test reads back is what [StoredSession.encode] wrote.
 */
class SharedMemoryStore : TokenStore {
    @Volatile private var record: ByteArray? = null

    override suspend fun read(): StoredSession? = record?.let { StoredSession.decode(it) }

    override suspend fun write(session: StoredSession) {
        record = session.encode()
    }

    override suspend fun clear() {
        record = null
    }

    /** A member of the stored record, or null (no record, or no such member). */
    fun stored(name: String): String? = record?.toString(Charsets.UTF_8)?.let { jsonString(it, name) }
}

/**
 * The server, asked directly — never through the SDK: what it now says about a
 * token the SDK holds or held.
 */
class ServerProbe(private val server: LiveServer) {
    private val http: HttpClient = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .version(HttpClient.Version.HTTP_1_1)
        .connectTimeout(Duration.ofSeconds(10))
        .build()

    class Answer(val status: Int, val body: String) {
        fun string(name: String): String? = jsonString(body, name)
        override fun toString(): String = "HTTP $status ${string("error") ?: ""}".trim()
    }

    val discovery: Answer by lazy { get("${server.issuer}/.well-known/openid-configuration") }

    fun endpoint(name: String): String = discovery.string(name) ?: throw AssertionError("discovery has no $name")

    fun get(url: String, bearer: String? = null): Answer {
        val builder = JdkHttpRequest.newBuilder(URI(url)).timeout(Duration.ofSeconds(30)).header("Accept", "application/json")
        bearer?.let { builder.header("Authorization", "Bearer $it") }
        val r = http.send(builder.GET().build(), BodyHandlers.ofString())
        return Answer(r.statusCode(), r.body())
    }

    fun postForm(url: String, vararg form: Pair<String, String>): Answer {
        val body = form.joinToString("&") { (k, v) -> "${URLEncoder.encode(k, Charsets.UTF_8)}=${URLEncoder.encode(v, Charsets.UTF_8)}" }
        val request = JdkHttpRequest.newBuilder(URI(url)).timeout(Duration.ofSeconds(30))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .POST(JdkHttpRequest.BodyPublishers.ofString(body))
            .build()
        val r = http.send(request, BodyHandlers.ofString())
        return Answer(r.statusCode(), r.body())
    }

    /** `grant_type=refresh_token` as a public client: what the server now says about [refreshToken]. */
    fun refresh(refreshToken: String): Answer = postForm(
        endpoint("token_endpoint"),
        "grant_type" to "refresh_token",
        "refresh_token" to refreshToken,
        "client_id" to server.clientId,
    )

    fun revoke(refreshToken: String): Answer = postForm(
        endpoint("revocation_endpoint"),
        "token" to refreshToken,
        "token_type_hint" to "refresh_token",
        "client_id" to server.clientId,
    )

    fun userinfo(accessToken: String): Answer = get(endpoint("userinfo_endpoint"), bearer = accessToken)
}

/** A form or query string as name → value (the last one wins; none of these repeat). */
fun formOf(encoded: String): Map<String, String> = encoded.split('&').filter { it.isNotEmpty() }.associate {
    URLDecoder.decode(it.substringBefore('='), Charsets.UTF_8) to URLDecoder.decode(it.substringAfter('=', ""), Charsets.UTF_8)
}

fun queryOf(url: String): Map<String, String> = formOf(URI(url).rawQuery.orEmpty())

/**
 * A top-level string member of a JSON object. Enough for what these tests read —
 * tokens, ids, URLs, names — without a JSON library the public API does not
 * offer. `\/` and `\"` are the only escapes these values can carry.
 */
fun jsonString(json: String, name: String): String? =
    Regex(""""${Regex.escape(name)}"\s*:\s*"((?:[^"\\]|\\.)*)"""").find(json)?.groupValues?.get(1)
        ?.replace("\\/", "/")?.replace("\\\"", "\"")

fun jsonNumber(json: String, name: String): Long? =
    Regex(""""${Regex.escape(name)}"\s*:\s*(-?[0-9]+)""").find(json)?.groupValues?.get(1)?.toLong()

private fun b64u(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

private fun sha256(s: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.US_ASCII))

/** RFC 7636 §4.2: BASE64URL(SHA256(ASCII(verifier))). Computed here, not by the SDK. */
fun s256(verifier: String): String = b64u(sha256(verifier))

/** OIDC Core §3.1.3.6: the left half of SHA-256 over the access token. Computed here, not by the SDK. */
fun atHashOf(accessToken: String): String = sha256(accessToken).let { b64u(it.copyOf(it.size / 2)) }

/** The decoded payload of a compact JWS, as text. */
fun jwtPayload(jwt: String): String = String(Base64.getUrlDecoder().decode(jwt.split('.')[1]), Charsets.UTF_8)

/** [jwt] with one signature character changed, so its signature no longer verifies. */
fun withBrokenSignature(jwt: String): String {
    val (h, p, s) = jwt.split('.')
    // Change a character in the middle of the signature (never the last, whose
    // low bits may be padding the decoder ignores).
    val i = s.length / 2
    val flipped = if (s[i] == 'A') 'B' else 'A'
    return "$h.$p.${s.substring(0, i)}$flipped${s.substring(i + 1)}"
}

/** A JSON body with one top-level string member's value replaced. */
fun replaceJsonString(json: String, name: String, value: String): String =
    Regex("""("${Regex.escape(name)}"\s*:\s*")((?:[^"\\]|\\.)*)(")""").replace(json) { it.groupValues[1] + value + it.groupValues[3] }

/** [response] with a new body and its Content-Type kept. */
fun withBody(response: HttpResponse, body: String): HttpResponse {
    val headers = response.header("Content-Type")?.let { mapOf("Content-Type" to listOf(it)) }.orEmpty()
    return HttpResponse(response.status, headers, body.toByteArray(Charsets.UTF_8))
}
