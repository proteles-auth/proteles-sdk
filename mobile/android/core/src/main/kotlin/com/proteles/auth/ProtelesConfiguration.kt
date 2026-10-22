package com.proteles.auth

import java.net.URI
import java.net.URISyntaxException

/**
 * What the SDK needs to know about the app and its tenant (docs/mobile-SDKs.md
 * §10.1). Everything that can never work is refused **here, at construction**,
 * with [ProtelesException.Configuration] — not at the first sign-in, where it
 * would surface as a server's 400 page in a browser the app cannot read.
 */
public class ProtelesConfiguration(
    /**
     * The tenant's issuer, exactly as the server spells it. Compared byte for byte
     * (§5.2 divergence 2): `https://auth.example.com/` is a different issuer from
     * `https://auth.example.com`.
     */
    public val issuer: String,
    /** The public client's id — one per app, registered by the tenant administrator (M4). */
    public val clientId: String,
    /** Registered exactly; sent identically to the authorization and token endpoints. */
    public val redirectUri: String,
    scopes: List<String> = DEFAULT_SCOPES,
    /** Where the browser lands after [ProtelesClient.signOut] ends the browser session; optional. */
    public val postLogoutRedirectUri: String? = null,
) {
    public val scopes: List<String> = scopes.toList()

    init {
        checkIssuer(issuer)
        // Visible ASCII, as the iOS SDK requires: it names the Keystore alias and
        // travels in every form and URL this SDK sends.
        if (clientId.isEmpty() || !clientId.all { it.code in 0x21..0x7E }) {
            throw ProtelesException.Configuration("clientId must be non-empty visible ASCII")
        }
        checkRedirectUri("redirectUri", redirectUri)
        postLogoutRedirectUri?.let { checkRedirectUri("postLogoutRedirectUri", it) }
        checkScopes(this.scopes)
    }

    /** The space-separated `scope` parameter. */
    public val scope: String get() = scopes.joinToString(" ")

    override fun toString(): String =
        "ProtelesConfiguration(issuer=$issuer, clientId=$clientId, redirectUri=$redirectUri, scopes=$scopes, postLogoutRedirectUri=$postLogoutRedirectUri)"

    public companion object {
        /** §10.1's default. `offline_access` is not in it: it does nothing here (trap 4). */
        public val DEFAULT_SCOPES: List<String> = listOf("openid", "profile", "email")

        /** §10.1: where an `http:` issuer — and so its discovery document's endpoints — may be. */
        internal val LOOPBACK_HOSTS: Set<String> = setOf("localhost", "127.0.0.1", "[::1]")
        private val NEVER_A_REDIRECT = setOf("javascript", "data", "vbscript", "mailto", "file")

        private fun fail(message: String): Nothing = throw ProtelesException.Configuration(message)

        private fun parse(what: String, value: String): URI {
            // The server's own first rule for a registrable redirect (docs/mobile-SDKs.md §2.1):
            // visible ASCII only, checked on the string as written.
            if (value.isEmpty() || !value.all { it.code in 0x21..0x7E }) {
                fail("$what must be non-empty visible ASCII (percent-encode anything else)")
            }
            val uri = try {
                URI(value)
            } catch (e: URISyntaxException) {
                fail("$what is not a valid URI: ${e.reason}")
            }
            if (uri.scheme == null) fail("$what must be an absolute URI")
            if (value.contains('#')) fail("$what must not contain a fragment")
            return uri
        }

        internal fun checkIssuer(issuer: String) {
            val uri = parse("issuer", issuer)
            when (uri.scheme) {
                "https" -> Unit
                "http" -> if (uri.host !in LOOPBACK_HOSTS) {
                    fail("issuer must be https: (http: is allowed only on localhost, 127.0.0.1 or [::1], for development)")
                }
                else -> fail("issuer must be an https: URL")
            }
            if (uri.host.isNullOrEmpty()) fail("issuer must name a host")
            if (uri.rawUserInfo != null) fail("issuer must not carry userinfo")
            // OpenID Connect Discovery §3: an issuer has no query and no fragment.
            if (uri.rawQuery != null) fail("issuer must not carry a query")
        }

        /**
         * The server's registrable-redirect rule (docs/mobile-SDKs.md §2.1), narrowed
         * where §10.1 narrows it: **no `http:` at all** — not `localhost`, which is
         * registrable but not port-exempt (trap 1), and, as settled 2026-09-25, not
         * the loopback IP literals either, which no native SDK can receive.
         *
         * **And no private-use scheme** (M7): the server
         * registers none, since a second app can claim any of them. What is left
         * is an `https` App Link on a domain whose `assetlinks.json` names the app.
         */
        internal fun checkRedirectUri(what: String, value: String) {
            val uri = parse(what, value)
            val scheme = uri.scheme.lowercase()
            when {
                scheme == "https" -> {
                    if (uri.host.isNullOrEmpty()) fail("$what: an https redirect must name a host")
                    if (uri.rawUserInfo != null) fail("$what must not carry userinfo")
                }
                scheme == "http" -> when (uri.host) {
                    "localhost" -> fail(
                        "$what: http://localhost is not port-exempt at this server (docs/mobile-SDKs.md §3 trap 1), and a native SDK " +
                            "cannot receive a loopback redirect; use an https App Link",
                    )
                    in LOOPBACK_HOSTS -> fail(
                        "$what: a loopback redirect needs a local HTTP listener, which neither native SDK runs (docs/mobile-SDKs.md §10.1); " +
                            "use an https App Link",
                    )
                    else -> fail("$what: http: is never a redirect for a native app (RFC 9700 §2.6); use an https App Link")
                }
                scheme in NEVER_A_REDIRECT -> fail("$what: $scheme: is never a redirect target")
                else -> fail(
                    "$what: \"$value\" uses the private-use scheme \"$scheme\", which the server does not register: a second app can claim it (M7). " +
                        "Use an https App Link on a domain whose assetlinks.json names this app",
                )
            }
        }

        internal fun checkScopes(scopes: List<String>) {
            if ("openid" !in scopes) fail("scopes must include openid: this SDK verifies an ID token on every sign-in")
            for (s in scopes) {
                // RFC 6749 §3.3 scope-token: %x21 / %x23-5B / %x5D-7E
                val ok = s.isNotEmpty() && s.all { it.code == 0x21 || it.code in 0x23..0x5B || it.code in 0x5D..0x7E }
                if (!ok) fail("scope \"$s\" is not a valid scope token")
            }
            if (scopes.toSet().size != scopes.size) fail("scopes must not repeat")
        }
    }
}
