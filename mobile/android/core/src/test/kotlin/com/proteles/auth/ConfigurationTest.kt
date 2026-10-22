package com.proteles.auth

import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** docs/mobile-SDKs.md §10.1: refused at construction, not at the first sign-in. */
class ConfigurationTest {
    private fun config(
        issuer: String = ISSUER,
        clientId: String = CLIENT_ID,
        redirectUri: String = REDIRECT,
        scopes: List<String> = ProtelesConfiguration.DEFAULT_SCOPES,
        postLogout: String? = null,
    ) = ProtelesConfiguration(issuer, clientId, redirectUri, scopes, postLogout)

    private fun refused(block: () -> Unit): String =
        assertFailsWith<ProtelesException.Configuration> { block() }.message.orEmpty()

    @Test
    fun `an app link is accepted`() {
        config(redirectUri = "https://app.example.com/oauth/callback")
        config(redirectUri = "https://app.example.com:8443/oauth/callback")
    }

    @ParameterizedTest
    @ValueSource(strings = ["http://127.0.0.1:51004/cb", "http://[::1]:51004/cb", "http://127.0.0.1/cb", "HTTP://127.0.0.1/cb"])
    fun `a loopback redirect is refused - no native SDK can receive one (10_1, settled 2026-09-25)`(uri: String) {
        assertContains(refused { config(redirectUri = uri) }, "loopback")
    }

    @Test
    fun `the defaults`() {
        val c = config()
        assertEquals(listOf("openid", "profile", "email"), c.scopes)
        assertEquals("openid profile email", c.scope)
        assertEquals(null, c.postLogoutRedirectUri)
    }

    @ParameterizedTest
    @ValueSource(strings = ["com.example.app:/callback", "com.example.app://callback", "myapp:/callback", "myapp://callback", "oauth:/redirect"])
    fun `no private-use scheme is a redirect, reverse-DNS included (M7)`(uri: String) {
        val message = refused { config(redirectUri = uri) }
        assertContains(message, "private-use scheme")
        assertContains(message, "App Link")
    }

    @ParameterizedTest
    @ValueSource(strings = ["http://localhost:51004/cb", "http://localhost:8080/", "http://localhost/cb"])
    fun `localhost is refused, with or without a port (trap 1)`(uri: String) {
        assertContains(refused { config(redirectUri = uri) }, "localhost")
    }

    @ParameterizedTest
    @ValueSource(strings = ["http://10.0.0.1/cb", "http://app.example.com/cb", "http://127.0.0.2/cb", "http://10.0.2.2:8080/cb"])
    fun `http on any other host is refused`(uri: String) {
        refused { config(redirectUri = uri) }
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "com.example.app:/cb#frag",
            "https://app.example.com/cb#",
            "com.example.app:callback", // opaque: not hierarchical
            "javascript:alert(1)",
            "data:text/html,hi",
            "vbscript:x",
            "mailto:a@example.com",
            "/relative/cb",
            "https://app.example.com/c b",
            "https:///no-host",
        ],
    )
    fun `fragments, opaque URIs and non-targets are refused`(uri: String) {
        refused { config(redirectUri = uri) }
    }

    @Test
    fun `the post-logout redirect is held to the same rules`() {
        config(postLogout = "https://app.example.com/signed-out")
        assertContains(refused { config(postLogout = "com.example.app:/signed-out") }, "private-use scheme")
        refused { config(postLogout = "http://localhost:4000/out") }
        refused { config(postLogout = "http://127.0.0.1:4000/out") }
    }

    @Test
    fun `the issuer must be https except on loopback`() {
        config(issuer = "https://auth.example.com")
        config(issuer = "https://auth.example.com/tenants/acme")
        config(issuer = "http://127.0.0.1:8080")
        config(issuer = "http://[::1]:8080")
        config(issuer = "http://localhost:8080") // §10.1: localhost counts as loopback for the issuer
        refused { config(issuer = "http://auth.example.com") }
        refused { config(issuer = "http://localhost.example.com:8080") }
        refused { config(issuer = "http://10.0.2.2:8080") }
        refused { config(issuer = "ftp://auth.example.com") }
        refused { config(issuer = "https://auth.example.com?tenant=a") }
        refused { config(issuer = "https://auth.example.com#x") }
        refused { config(issuer = "auth.example.com") }
        refused { config(issuer = "") }
    }

    @Test
    fun `the issuer is kept byte for byte, trailing slash and all`() {
        assertEquals("https://auth.example.com/", config(issuer = "https://auth.example.com/").issuer)
    }

    @Test
    fun `client id and scopes are checked`() {
        refused { config(clientId = "") }
        refused { config(clientId = "has space") }
        assertContains(refused { config(scopes = listOf("profile", "email")) }, "openid")
        refused { config(scopes = listOf("openid", "")) }
        refused { config(scopes = listOf("openid", "two words")) }
        refused { config(scopes = listOf("openid", "openid")) }
        config(scopes = listOf("openid", "offline_access", "api:read"))
    }

    @ParameterizedTest
    @ValueSource(strings = ["clïent", "客户端", "a\u00A0b", "tab\tid", "del\u007F", "nbsp\u2007", "emoji\uD83D\uDE00"])
    fun `client id must be visible ASCII, as on iOS`(clientId: String) {
        assertContains(refused { config(clientId = clientId) }, "visible ASCII")
    }

    @Test
    fun `every visible ASCII client id is accepted`() {
        config(clientId = (0x21..0x7E).map { it.toChar() }.joinToString(""))
        config(clientId = "com.example.app")
    }
}
