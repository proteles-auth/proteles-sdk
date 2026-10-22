package com.proteles.auth

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI

/** One HTTP request. The SDK sends only GET (discovery, keys) and form POSTs. */
public class HttpRequest(
    public val method: String,
    public val url: String,
    public val headers: Map<String, String> = emptyMap(),
    public val body: ByteArray? = null,
) {
    /** The body as text (every body this SDK sends is a UTF-8 form). */
    public val bodyText: String? get() = body?.toString(Charsets.UTF_8)

    override fun toString(): String = "$method $url"
}

/** One HTTP response. Header names are matched case-insensitively. */
public class HttpResponse(
    public val status: Int,
    headers: Map<String, List<String>> = emptyMap(),
    public val body: ByteArray = ByteArray(0),
) {
    private val headers: Map<String, List<String>> = headers.mapKeys { it.key.lowercase() }

    /** The first value of header [name], or null. */
    public fun header(name: String): String? = headers[name.lowercase()]?.firstOrNull()
}

/**
 * How the SDK talks HTTP. The default is [HttpUrlConnectionTransport], which runs
 * on Android and the JVM alike; tests and apps with their own HTTP stack (for
 * certificate pinning, say) supply another.
 *
 * Contract: return every HTTP response, whatever its status; throw
 * [IOException] only when there is no response at all. Never follow redirects:
 * a token request that followed one would re-send its form — code, verifier,
 * refresh token — to wherever the redirect pointed.
 */
public fun interface Transport {
    public suspend fun send(request: HttpRequest): HttpResponse
}

/**
 * [Transport] over `java.net.HttpURLConnection`: redirects not followed, no
 * response cache, 10 s connect and read timeouts, responses capped at 1 MiB.
 *
 * **Cookies:** this SDK sets none and installs no cookie handler. But
 * `HttpURLConnection` has no per-request way to opt out of the process-wide
 * `java.net.CookieHandler`: if the app has installed one
 * (`CookieHandler.setDefault`), it adds its cookies for the issuer's host to
 * these requests and stores any the issuer sets. The iOS SDK's transport is
 * cookie-free. An app that installs a process-wide cookie handler and wants
 * the SDK's requests kept out of it passes its own [Transport].
 */
public class HttpUrlConnectionTransport(
    private val connectTimeoutMillis: Int = 10_000,
    private val readTimeoutMillis: Int = 10_000,
    private val maxResponseBytes: Int = 1 shl 20,
) : Transport {
    override suspend fun send(request: HttpRequest): HttpResponse = runInterruptible(Dispatchers.IO) {
        val connection = URI(request.url).toURL().openConnection() as HttpURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = connectTimeoutMillis
            connection.readTimeout = readTimeoutMillis
            connection.requestMethod = request.method
            for ((name, value) in request.headers) connection.setRequestProperty(name, value)
            val body = request.body
            if (body != null) {
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            val stream: InputStream? = if (status >= 400) connection.errorStream else connection.inputStream
            val bytes = stream?.use { readCapped(it) } ?: ByteArray(0)
            val headers = connection.headerFields.orEmpty().filterKeys { it != null }.mapKeys { it.key!! }
            HttpResponse(status, headers, bytes)
        } finally {
            connection.disconnect()
        }
    }

    private fun readCapped(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val n = input.read(buffer)
            if (n < 0) return out.toByteArray()
            if (out.size() + n > maxResponseBytes) throw IOException("response larger than $maxResponseBytes bytes")
            out.write(buffer, 0, n)
        }
    }
}
