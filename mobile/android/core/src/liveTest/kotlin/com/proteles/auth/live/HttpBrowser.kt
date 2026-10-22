package com.proteles.auth.live

import com.proteles.auth.BrowserHop
import com.proteles.auth.ProtelesException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList

/**
 * The browser, played over HTTP: what a Custom Tab does between the SDK opening
 * the authorization URL and the redirect coming back — the steps
 * mobile/live/README.md "Driving the browser hop in a test" lists, and
 * curl-check.sh steps 2–4 prove.
 *
 * It follows redirects itself until one is addressed to the return URI, and
 * returns that URL without following it — and the page that moves on by meta
 * refresh, which the server answers a sign-in, consent or logout form with in
 * place of a 303 whose chain ends at the app, the same way. A page on the way is answered the way
 * a person would answer it: the login form is filled in and posted with its own
 * hidden fields (`redirect`, `csrf`), a consent page is allowed, and the
 * end-session confirmation is confirmed. Anything else is a failure that names
 * the page.
 *
 * **Cookies are kept by hand**, one jar per browser. The server's cookies are
 * `__Host-` and `Secure` even on plain-http localhost, and `java.net.CookieManager`
 * (JDK 17) stores such a cookie from an http response but never sends it back
 * to an http URL — the login's CSRF check would then fail. Only one host is ever
 * visited, so the jar is a name → value map.
 */
class HttpBrowser(private val username: String, private val password: String) : BrowserHop {
    private val http: HttpClient = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        // No h2c upgrade offer on plain http: a browser does not make one either.
        .version(HttpClient.Version.HTTP_1_1)
        .connectTimeout(Duration.ofSeconds(10))
        .build()

    private val cookies = LinkedHashMap<String, String>()

    /** Every request this browser made, as `METHOD path → status`, across all [open] calls. */
    val trace: MutableList<String> = CopyOnWriteArrayList()

    /** The URLs the SDK asked this browser to open. */
    val opened: MutableList<String> = CopyOnWriteArrayList()

    /** The URLs this browser handed back to the SDK. */
    val returned: MutableList<String> = CopyOnWriteArrayList()

    /** How many times the login form was filled in, and a consent page allowed. */
    @Volatile var logins: Int = 0
        private set

    @Volatile var consents: Int = 0
        private set

    /** Rewrites the URL the SDK asked to open before it is requested (a negative control). */
    @Volatile var rewriteOpened: ((String) -> String)? = null

    /** Rewrites the return URL before it is handed back to the SDK (a negative control). */
    @Volatile var rewriteReturned: ((String) -> String)? = null

    fun hasCookie(name: String): Boolean = synchronized(cookies) { name in cookies }

    override suspend fun open(url: String, returnUri: String?): String = withContext(Dispatchers.IO) {
        opened += url
        val back = navigate(rewriteOpened?.invoke(url) ?: url, returnUri)
        val handed = rewriteReturned?.invoke(back) ?: back
        returned += handed
        handed
    }

    private fun navigate(start: String, returnUri: String?): String {
        var method = "GET"
        var target = start
        var form: List<Pair<String, String>>? = null
        var loginsHere = 0
        repeat(MAX_STEPS) {
            val response = send(method, target, form)
            val status = response.statusCode()
            trace += "$method ${pathOf(target)} → $status"
            when (status) {
                301, 302, 303, 307, 308 -> {
                    val location = response.headers().firstValue("location").orElse(null)
                        ?: throw AssertionError("$method $target answered $status with no Location")
                    // Handed back exactly as the server wrote it: the SDK does the checking.
                    if (isReturn(location, returnUri)) return location
                    target = hop(target, location, returnUri)
                    method = "GET"
                    form = null
                }
                200 -> {
                    val page = response.body()
                    val refresh = refreshTarget(page)
                    if (refresh != null) {
                        if (isReturn(refresh, returnUri)) return refresh
                        target = hop(target, refresh, returnUri)
                        method = "GET"
                        form = null
                        return@repeat
                    }
                    val action = formAction(page)
                        ?: throw AssertionError("$method ${pathOf(target)} is a page with no form: ${summary(page)}")
                    val hidden = hiddenInputs(page)
                    form = when (action) {
                        "/login" -> {
                            loginsHere++
                            if (loginsHere > 1) throw AssertionError("the login form came back after a sign-in: ${summary(page)}")
                            logins++
                            hidden + listOf("username" to username, "password" to password)
                        }
                        "/oauth/authorize/decision" -> {
                            consents++
                            hidden + ("decision" to "allow")
                        }
                        // The end-session confirmation page: its one button has no name.
                        "/oauth/logout" -> hidden
                        else -> throw AssertionError("a form this browser does not know how to answer ($action): ${summary(page)}")
                    }
                    method = "POST"
                    target = URI(target).resolve(action).toString()
                }
                else -> throw AssertionError("$method ${pathOf(target)} answered HTTP $status: ${summary(response.body())}")
            }
        }
        if (returnUri == null) throw ProtelesException.Cancelled()
        throw AssertionError("no redirect to $returnUri after $MAX_STEPS requests: ${trace.takeLast(MAX_STEPS)}")
    }

    private fun isReturn(location: String, returnUri: String?): Boolean =
        returnUri != null && (location == returnUri || location.startsWith("$returnUri?"))

    /** Where `location`, answered to a request for `from`, sends the browser — an http(s) URL or a failure. */
    private fun hop(from: String, location: String, returnUri: String?): String {
        val next = URI(from).resolve(location)
        if (next.scheme != "http" && next.scheme != "https") {
            throw AssertionError("the server sent the browser to $location, which is not the return URI $returnUri")
        }
        return next.toString()
    }

    private fun send(method: String, url: String, form: List<Pair<String, String>>?): HttpResponse<String> {
        val builder = HttpRequest.newBuilder(URI(url)).timeout(Duration.ofSeconds(30))
        val jar = synchronized(cookies) { cookies.entries.joinToString("; ") { "${it.key}=${it.value}" } }
        if (jar.isNotEmpty()) builder.header("Cookie", jar)
        if (form != null) {
            val body = form.joinToString("&") { (k, v) -> "${enc(k)}=${enc(v)}" }
            builder.header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(body))
        } else {
            builder.GET()
        }
        val response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        keepCookies(response.headers().allValues("set-cookie"))
        return response
    }

    private fun keepCookies(setCookies: List<String>) = synchronized(cookies) {
        for (header in setCookies) {
            val pair = header.substringBefore(';')
            val name = pair.substringBefore('=').trim()
            if (name.isEmpty()) continue
            val attributes = header.substringAfter(';', "").lowercase()
            val deleted = Regex("""max-age\s*=\s*0\b""").containsMatchIn(attributes) || attributes.contains("expires=thu, 01 jan 1970")
            if (deleted) cookies.remove(name) else cookies[name] = pair.substringAfter('=').trim()
        }
    }

    companion object {
        private const val MAX_STEPS = 12

        private fun enc(s: String): String = URLEncoder.encode(s, Charsets.UTF_8)

        private fun pathOf(url: String): String = URI(url).rawPath ?: url

        /**
         * The target of the server's page that moves on:
         * its `<meta http-equiv="refresh" content="0;url=…">`, entity-decoded.
         */
        fun refreshTarget(page: String): String? =
            Regex("""<meta http-equiv="refresh" content="0;url=([^"]*)"""").find(page)?.groupValues?.get(1)?.let(::unescape)

        /** The first form's `action`, entity-decoded. */
        fun formAction(page: String): String? =
            Regex("""<form\b[^>]*\baction="([^"]*)"""", RegexOption.IGNORE_CASE).find(page)?.groupValues?.get(1)?.let(::unescape)

        /** The first form's hidden inputs, in document order, entity-decoded. */
        fun hiddenInputs(page: String): List<Pair<String, String>> {
            val start = Regex("""<form\b""", RegexOption.IGNORE_CASE).find(page)?.range?.first ?: return emptyList()
            val end = page.indexOf("</form>", start).takeIf { it >= 0 } ?: page.length
            return Regex("""<input\b[^>]*>""", RegexOption.IGNORE_CASE).findAll(page.substring(start, end)).mapNotNull { tag ->
                val attrs = Regex("""([a-zA-Z_:-]+)="([^"]*)"""").findAll(tag.value).associate { it.groupValues[1].lowercase() to unescape(it.groupValues[2]) }
                if (attrs["type"]?.lowercase() != "hidden") return@mapNotNull null
                val name = attrs["name"] ?: return@mapNotNull null
                name to attrs["value"].orEmpty()
            }.toList()
        }

        /** The five entities the server's HTML escaping writes, and the numeric forms. */
        private fun unescape(s: String): String =
            Regex("""&(#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos);""").replace(s) { m ->
                val e = m.groupValues[1]
                when {
                    e.startsWith("#x") -> String(Character.toChars(e.substring(2).toInt(16)))
                    e.startsWith("#") -> String(Character.toChars(e.substring(1).toInt()))
                    e == "amp" -> "&"
                    e == "lt" -> "<"
                    e == "gt" -> ">"
                    e == "quot" -> "\""
                    else -> "'"
                }
            }

        /** A page, briefly: its title, first heading and any error text. */
        private fun summary(page: String): String {
            fun first(tag: String) = Regex("""<$tag\b[^>]*>(.*?)</$tag>""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
                .find(page)?.groupValues?.get(1)?.replace(Regex("<[^>]+>"), "")?.trim()
            val error = Regex("""class="[^"]*error[^"]*"[^>]*>(.*?)<""", RegexOption.IGNORE_CASE).find(page)?.groupValues?.get(1)?.trim()
            return listOfNotNull(first("title"), first("h1"), error).joinToString(" | ").ifEmpty { page.take(200) }
        }
    }
}
