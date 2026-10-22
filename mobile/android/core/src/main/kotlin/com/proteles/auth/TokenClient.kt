package com.proteles.auth

import java.io.IOException
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import kotlin.coroutines.cancellation.CancellationException

/** A successful token-endpoint response (RFC 6749 §5.1). */
internal class TokenResponse(
    val accessToken: String,
    val expiresIn: Long,
    val refreshToken: String?,
    val idToken: String?,
    val scope: String?,
)

/**
 * The token and revocation endpoints, for a public client: `client_id` in the
 * form body and no secret, ever (docs/mobile-SDKs.md §10.2 step 5, M4).
 */
internal class TokenClient(
    private val transport: Transport,
    private val clientId: String,
    private val clock: Clock,
    /** Shared with the rest of the client: a 429 from anywhere closes it (§10.9 item 3). */
    private val rateLimits: RateLimitGate = RateLimitGate(clock),
) {
    /**
     * `grant_type=authorization_code` with the PKCE verifier and the identical
     * redirect URI. [onIssued] is handed the refresh token as soon as a 200 body
     * parses as a JSON object carrying one — before anything else is checked —
     * so a sign-in that fails after this point can revoke it (§10.9 item 7).
     */
    suspend fun exchangeCode(
        tokenEndpoint: String,
        code: String,
        redirectUri: String,
        codeVerifier: String,
        onIssued: (suspend (String) -> Unit)? = null,
    ): TokenResponse =
        tokenRequest(
            tokenEndpoint,
            listOf(
                "grant_type" to "authorization_code",
                "code" to code,
                "redirect_uri" to redirectUri,
                "client_id" to clientId,
                "code_verifier" to codeVerifier,
            ),
            onIssued,
        )

    /**
     * `grant_type=refresh_token`. The response's refresh token replaces the
     * presented one (§2.3), and the server revoked the presented one before it
     * answered — so [onRotated] is handed the new refresh token **as soon as a
     * 200 body parses as a JSON object carrying one**, before any other member is
     * checked. Whatever else is wrong with the response, the only live
     * credential is not dropped. An exception from [onRotated] propagates.
     */
    suspend fun refresh(tokenEndpoint: String, refreshToken: String, onRotated: suspend (String) -> Unit): TokenResponse =
        tokenRequest(
            tokenEndpoint,
            listOf(
                "grant_type" to "refresh_token",
                "refresh_token" to refreshToken,
                "client_id" to clientId,
            ),
            onRotated,
        )

    /** RFC 7009. Returns normally only on HTTP 200; anything else is raised for the caller to report. */
    suspend fun revoke(revocationEndpoint: String, token: String, hint: String) {
        val response = post(
            revocationEndpoint,
            listOf("token" to token, "token_type_hint" to hint, "client_id" to clientId),
        )
        if (response.status != 200) throw endpointError(response)
    }

    private suspend fun tokenRequest(
        endpoint: String,
        form: List<Pair<String, String>>,
        onRefreshToken: (suspend (String) -> Unit)? = null,
    ): TokenResponse {
        // A request into a latched bucket keeps it latched (§2.5): honouring
        // Retry-After means not sending.
        rateLimits.remaining()?.let { throw ProtelesException.RateLimited(it) }
        val response = post(endpoint, form)
        if (response.status != 200) throw endpointError(response)
        val body = try {
            Json.parseObjectUtf8(response.body)
        } catch (e: JsonSyntaxException) {
            throw invalidResponse("the token response is not a JSON object")
        }
        // Before anything else is checked: on a refresh, this is the only live
        // credential; on a code exchange, the one a failed sign-in must revoke.
        if (onRefreshToken != null) (body["refresh_token"] as? JsonString)?.value?.takeIf { it.isNotEmpty() }?.let { onRefreshToken(it) }
        val accessToken = body.string("access_token")
        if (accessToken.isNullOrEmpty()) throw invalidResponse("the token response has no access_token")
        val tokenType = body.string("token_type")
        if (!tokenType.equals("Bearer", ignoreCase = true)) {
            throw invalidResponse("the token response's token_type is ${tokenType ?: "absent"}, not Bearer")
        }
        // Honoured as sent, never assumed (§2.3: a SAML session deadline shortens it).
        // Never 0 from this server (it refuses to mint a token that
        // would expire as it is issued), and some libraries read 0 as "never
        // expires": refused, as the iOS SDK refuses it. Kept in whole seconds,
        // rounded down — but a positive lifetime never becomes none, which would
        // make every validAccessToken rotate.
        val expiresIn = body.number("expires_in")?.double
        if (expiresIn == null || !expiresIn.isFinite() || expiresIn <= 0) {
            throw invalidResponse("the token response has no positive expires_in")
        }
        fun optionalString(name: String): String? = when (val v = body[name]) {
            null, JsonNull -> null
            is JsonString -> v.value.ifEmpty { null }
            else -> throw invalidResponse("the token response's $name is not a string")
        }
        return TokenResponse(
            accessToken = accessToken,
            expiresIn = maxOf(1L, expiresIn.toLong()),
            refreshToken = optionalString("refresh_token"),
            idToken = optionalString("id_token"),
            scope = optionalString("scope"),
        )
    }

    private suspend fun post(url: String, form: List<Pair<String, String>>): HttpResponse {
        val request = HttpRequest(
            method = "POST",
            url = url,
            headers = mapOf(
                "Content-Type" to "application/x-www-form-urlencoded",
                "Accept" to "application/json",
            ),
            body = PercentEncoding.form(form).toByteArray(Charsets.UTF_8),
        )
        return sendOrNetworkError(transport, request)
    }

    private fun endpointError(response: HttpResponse): ProtelesException {
        if (response.status == 429) return rateLimits.close(response)
        val body = try {
            Json.parseObjectUtf8(response.body)
        } catch (e: JsonSyntaxException) {
            null
        }
        if (response.status >= 500) {
            // A deploy, an overloaded server, a proxy with no upstream: "try later",
            // as discovery and the key set report it — not a refusal.
            val error = body?.string("error")?.let { " ($it)" }.orEmpty()
            return ProtelesException.Network("the server answered HTTP ${response.status}$error", httpStatus = response.status)
        }
        return ProtelesException.TokenEndpointError(
            error = body?.string("error"),
            errorDescription = body?.string("error_description"),
            httpStatus = response.status,
        )
    }

    private fun invalidResponse(description: String) =
        ProtelesException.TokenEndpointError("invalid_response", description, 200)
}

/**
 * After a 429 — from the token endpoint, discovery or the key set — no request
 * goes to the token endpoint, no refresh is attempted and no sign-in opens the
 * browser until the wait has passed (docs/mobile-SDKs.md §10.9 items 3 and 8).
 * The wait is `Retry-After`, capped at [MAX_WAIT_SECONDS], or
 * [DEFAULT_WAIT_SECONDS] when the server sent none this SDK can read. It lives
 * in memory, one per client.
 */
internal class RateLimitGate(private val clock: Clock) {
    @Volatile private var notBefore: Long = Long.MIN_VALUE

    /** Seconds until requests may be sent again, or null when they may be sent now. */
    fun remaining(): Long? {
        val now = clock.epochSeconds()
        val until = notBefore
        return if (now < until) until - now else null
    }

    /** Closes the gate for [response], a 429, and returns the error that reports the wait. */
    fun close(response: HttpResponse): ProtelesException.RateLimited {
        val now = clock.epochSeconds()
        val wait = parseRetryAfter(response.header("Retry-After"), now) ?: DEFAULT_WAIT_SECONDS
        val until = saturatingAdd(now, wait)
        // Two 429s in flight at once: the later deadline stands.
        synchronized(this) { if (until > notBefore) notBefore = until }
        return ProtelesException.RateLimited(wait)
    }

    companion object {
        /** §10.9 item 3: a 429 without a usable `Retry-After` backs off this long. */
        const val DEFAULT_WAIT_SECONDS: Long = 60

        /** §10.9 item 3: `Retry-After` is capped here, however far off the server says. */
        const val MAX_WAIT_SECONDS: Long = 3600
    }
}

/** [a] + [b] for a non-negative [b], held at [Long.MAX_VALUE] rather than wrapping negative. */
internal fun saturatingAdd(a: Long, b: Long): Long = if (b > Long.MAX_VALUE - a) Long.MAX_VALUE else a + b

/** Sends [request]; a transport failure (no response at all) becomes [ProtelesException.Network]. */
internal suspend fun sendOrNetworkError(transport: Transport, request: HttpRequest): HttpResponse = try {
    transport.send(request)
} catch (e: CancellationException) {
    throw e
} catch (e: ProtelesException) {
    throw e
} catch (e: IOException) {
    throw ProtelesException.Network("could not reach ${hostOf(request.url)}: ${e.message ?: e.javaClass.simpleName}", e)
} catch (e: RuntimeException) {
    throw ProtelesException.Network("could not reach ${hostOf(request.url)}: ${e.message ?: e.javaClass.simpleName}", e)
}

private fun hostOf(url: String): String = try {
    java.net.URI(url).host ?: url
} catch (e: Exception) {
    "the server"
}

/**
 * `Retry-After` (RFC 9110 §10.2.3): delta-seconds or an HTTP-date. Returns
 * seconds from [nowEpochSeconds], never negative and never more than
 * [RateLimitGate.MAX_WAIT_SECONDS] (§10.9 item 3: a server's "come back next
 * week" is read as an hour); null when absent or unreadable.
 */
internal fun parseRetryAfter(value: String?, nowEpochSeconds: Long): Long? {
    val v = value?.trim().orEmpty()
    if (v.isEmpty()) return null
    val seconds = if (v.all { it in '0'..'9' }) {
        v.toLongOrNull() ?: Long.MAX_VALUE
    } else {
        try {
            val at = ZonedDateTime.parse(v, DateTimeFormatter.RFC_1123_DATE_TIME).toEpochSecond()
            maxOf(0L, at - nowEpochSeconds)
        } catch (e: DateTimeParseException) {
            return null
        }
    }
    return minOf(seconds, RateLimitGate.MAX_WAIT_SECONDS)
}
