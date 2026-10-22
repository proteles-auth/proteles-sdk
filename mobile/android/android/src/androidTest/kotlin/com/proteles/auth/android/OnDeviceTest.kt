package com.proteles.auth.android

import android.accessibilityservice.AccessibilityService
import android.app.Activity
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import com.proteles.auth.BrowserHop
import com.proteles.auth.Clock
import com.proteles.auth.HttpResponse
import com.proteles.auth.ProtelesClient
import com.proteles.auth.ProtelesConfiguration
import com.proteles.auth.ProtelesException
import com.proteles.auth.SignOutResult
import com.proteles.auth.StoredSession
import com.proteles.auth.Transport
import com.proteles.auth.UnreadableSessionException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.URLDecoder
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.util.Base64

/** A plain Activity to start sign-ins from. */
class TestHostActivity : Activity()

/**
 * What only a device can show: the Keystore-backed store, and the browser hop
 * through a real Custom Tab, RedirectActivity and AuthorizationActivity.
 */
@RunWith(AndroidJUnit4::class)
class OnDeviceTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    /** The test app's redirect: an https host its manifest filters for (M7: no private-use scheme). */
    private val redirectBase = "https://redirect.proteles.test"
    private lateinit var scenario: ActivityScenario<TestHostActivity>
    private lateinit var host: Activity

    @Before
    fun launchHost() {
        scenario = ActivityScenario.launch(TestHostActivity::class.java)
        scenario.onActivity { host = it }
    }

    @After
    fun closeHost() {
        scenario.close()
    }

    // --- the store -----------------------------------------------------------

    private fun sampleSession(access: String = "at-1") = StoredSession.decode(
        """{"v":1,"issuer":"https://auth.example.test","clientId":"device-test","accessToken":"$access","obtainedAt":1800000000,"expiresAt":1800000900,"refreshToken":"rt-1","claims":"{\"sub\":\"user-1\"}"}"""
            .toByteArray(),
    )

    @Test
    fun keystoreStoreRoundTripsUnderAKeystoreKey(): Unit = runBlocking {
        val clientId = "device-test-${System.nanoTime()}"
        val store = KeystoreTokenStore.create(context, clientId)
        store.clear()
        assertNull(store.read())
        store.write(sampleSession())
        assertArrayEquals(sampleSession().encode(), store.read()!!.encode())

        // The key lives in the Android Keystore under the documented alias, and is not exportable.
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue(keyStore.containsAlias("com.proteles.auth.$clientId"))
        assertNull((keyStore.getKey("com.proteles.auth.$clientId", null) as javax.crypto.SecretKey).encoded)

        // On disk: in noBackupFilesDir, and not in the clear.
        val file = File(context.noBackupFilesDir, "com.proteles.auth.${KeystoreTokenStore.digest(clientId)}.session")
        assertTrue(file.isFile)
        val raw = String(file.readBytes(), Charsets.ISO_8859_1)
        assertFalse(raw.contains("at-1") || raw.contains("rt-1") || raw.contains("user-1"))

        // Tampered: unreadable (the client reads that as signed out, and sign-out
        // reports it as a failed revocation); the next write replaces it.
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        file.writeBytes(bytes)
        try {
            store.read()
            fail("read a tampered record")
        } catch (e: UnreadableSessionException) {
            // expected
        }

        store.write(sampleSession("at-2"))
        assertEquals("at-2", String(store.read()!!.encode()).substringAfter("\"accessToken\":\"").substringBefore('"'))
        store.clear()
        assertNull(store.read())
        keyStore.deleteEntry("com.proteles.auth.$clientId")
    }

    // --- the browser hop -----------------------------------------------------

    /**
     * Waits until AuthorizationActivity has put the browser in front of itself.
     * Generous: on a freshly booted emulator the first run timed out at 20 s
     * (in this wait or the one after it; the cause was not captured — Chrome's
     * first start, which also shows its first-run screen, is the likely one).
     */
    private suspend fun waitForBrowserInFront() {
        withTimeout(90_000) {
            while (true) {
                var covered = false
                instrumentation.runOnMainSync {
                    val registry = ActivityLifecycleMonitorRegistry.getInstance()
                    covered = listOf(Stage.PAUSED, Stage.STOPPED).any { stage ->
                        registry.getActivitiesInStage(stage).any { it is AuthorizationActivity }
                    }
                }
                if (covered) return@withTimeout
                delay(200)
            }
        }
        delay(1_000) // let the Custom Tab settle
    }

    /** What the browser does when the server redirects to the app: a VIEW intent for the redirect URI. */
    private fun deliverRedirect(uri: String) {
        context.startActivity(
            Intent(Intent.ACTION_VIEW, Uri.parse(uri))
                .addCategory(Intent.CATEGORY_BROWSABLE)
                .setPackage(context.packageName)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }

    @Test
    fun theRedirectComesBackThroughRedirectActivity(): Unit = runBlocking {
        val hop = CustomTabsBrowserHop(host)
        val returned = async(Dispatchers.Default) { hop.open("https://example.com/authorize?probe=1", "$redirectBase/cb") }
        waitForBrowserInFront()
        val callback = "$redirectBase/cb?code=abc&state=s-1&iss=https%3A%2F%2Fauth.example.test"
        deliverRedirect(callback)
        assertEquals(callback, withTimeout(60_000) { returned.await() })
    }

    @Test
    fun closingTheBrowserIsCancelled(): Unit = runBlocking {
        val hop = CustomTabsBrowserHop(host)
        val outcome = async(Dispatchers.Default) { runCatching { hop.open("https://example.com/authorize?probe=2", "$redirectBase/cb") } }
        waitForBrowserInFront()
        withTimeout(90_000) {
            // Back until the browser is gone (a first-run screen can take one more).
            while (!outcome.isCompleted) {
                instrumentation.uiAutomation.performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
                delay(2_000)
            }
        }
        val error = outcome.await().exceptionOrNull()
        assertTrue("expected Cancelled, got $error", error is ProtelesException.Cancelled)
    }

    @Test
    fun aReturnUriTheAppDidNotDeclareIsRefusedBeforeTheBrowserOpens(): Unit = runBlocking {
        try {
            CustomTabsBrowserHop(host).open("https://example.com/authorize", "https://undeclared.proteles.test/cb")
            fail("an undeclared return URI was accepted")
        } catch (e: ProtelesException.Configuration) {
            assertTrue(e.message!!.contains("RedirectActivity"))
        }
    }

    @Test
    fun aRedirectFilterWithoutCategoryDefaultIsRefused() {
        // Positive control: the README's filter passes.
        RedirectActivity.checkDeclared(context, "$redirectBase/cb")
        try {
            RedirectActivity.checkDeclared(context, "https://nodefault.proteles.test/cb")
            fail("a filter a browser cannot reach was accepted")
        } catch (e: ProtelesException.Configuration) {
            assertTrue(e.message!!.contains("DEFAULT"))
        }
    }

    @Test
    fun theBrowserIsAnInstalledBrowserWithCustomTabs() {
        val pm = context.packageManager
        val browsers = Browsers.installedBrowsers(pm)
        assertTrue("no browser found: $browsers", browsers.isNotEmpty())
        val choice = Browsers.choose(null, browsers) { Browsers.supportsCustomTabs(pm, it) }
        assertTrue("expected a Custom Tab, got $choice from $browsers", choice is Browsers.Choice.CustomTab)
    }

    @Test
    fun theSessionDirectoryCanBeSynced() {
        // The durability half of KeystoreTokenStore.write: fsync on the directory works here.
        assertTrue(fsyncDirectory(context.noBackupFilesDir))
    }

    // --- a whole sign-in on the device, with only the server scripted ---------

    private val b64u: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
    private fun b64(bytes: ByteArray) = b64u.encodeToString(bytes)
    private fun unsigned(b: ByteArray) = if (b.size > 1 && b[0] == 0.toByte()) b.copyOfRange(1, b.size) else b

    @Test
    fun aFullSignInPersistsToTheKeystoreStoreAndSignOutClearsIt(): Unit = runBlocking {
        val issuer = "https://auth.example.test"
        val clientId = "device-e2e-${System.nanoTime()}"
        val keys = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val pub = keys.public as RSAPublicKey
        val jwks = """{"keys":[{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":"${b64(unsigned(pub.modulus.toByteArray()))}","e":"${b64(unsigned(pub.publicExponent.toByteArray()))}"}]}"""
        val now = System.currentTimeMillis() / 1000
        var nonce = ""
        fun idToken(accessToken: String): String {
            val atHash = b64(MessageDigest.getInstance("SHA-256").digest(accessToken.toByteArray()).copyOf(16))
            val header = b64("""{"alg":"RS256","kid":"k1"}""".toByteArray())
            val payload = b64("""{"iss":"$issuer","sub":"user-1","aud":"$clientId","exp":${now + 900},"iat":$now,"nonce":"$nonce","at_hash":"$atHash","preferred_username":"alice"}""".toByteArray())
            val sig = Signature.getInstance("SHA256withRSA").apply {
                initSign(keys.private)
                update("$header.$payload".toByteArray())
            }.sign()
            return "$header.$payload.${b64(sig)}"
        }
        val requests = mutableListOf<String>()
        val transport = Transport { request ->
            requests.add("${request.method} ${request.url}")
            val body = when {
                request.url.endsWith("/.well-known/openid-configuration") ->
                    """{"issuer":"$issuer","authorization_endpoint":"https://example.com/authorize","token_endpoint":"$issuer/oauth/token","jwks_uri":"$issuer/jwks","revocation_endpoint":"$issuer/oauth/revoke","end_session_endpoint":"$issuer/oauth/logout"}"""
                request.url.endsWith("/jwks") -> jwks
                request.url.endsWith("/oauth/token") ->
                    """{"access_token":"at-device","token_type":"Bearer","expires_in":900,"refresh_token":"rt-device","id_token":"${idToken("at-device")}"}"""
                request.url.endsWith("/oauth/revoke") -> ""
                else -> error("unexpected ${request.url}")
            }
            HttpResponse(200, emptyMap(), body.toByteArray())
        }
        val configuration = ProtelesConfiguration(issuer, clientId, "$redirectBase/oauth/callback")
        val client = ProtelesClient(
            configuration,
            KeystoreTokenStore.create(context, clientId),
            FileCrossProcessLock.forClient(context, clientId),
            transport,
            Clock.SYSTEM,
        )
        // The real Custom Tabs hop; the test plays the server's redirect with the request's own state.
        val browser = object : BrowserHop {
            override suspend fun open(url: String, returnUri: String?): String {
                val query = Uri.parse(url)
                nonce = query.getQueryParameter("nonce")!!
                val state = query.getQueryParameter("state")!!
                val real = CustomTabsBrowserHop(host)
                val pending = async(Dispatchers.Default) { real.open(url, returnUri) }
                waitForBrowserInFront()
                deliverRedirect("$returnUri?code=the-code&state=$state&iss=${java.net.URLEncoder.encode(issuer, "UTF-8")}")
                return withTimeout(60_000) { pending.await() }
            }
        }
        val claims = client.signIn(browser)
        assertEquals("alice", claims.preferredUsername)
        assertEquals("at-device", client.validAccessToken())
        assertEquals("user-1", client.currentClaims()!!.subject)
        // A second client — as another process would build — reads the same Keystore-sealed session.
        val second = ProtelesClient(configuration, KeystoreTokenStore.create(context, clientId), FileCrossProcessLock.forClient(context, clientId), transport)
        assertEquals("user-1", second.currentClaims()!!.subject)

        val result = client.signOut()
        assertEquals(SignOutResult.Revocation.Revoked, result.revocation)
        assertNull(client.currentClaims())
        assertNull(second.currentClaims())
        assertNotNull(requests.find { it.endsWith("/oauth/revoke") })
        assertTrue(URLDecoder.decode(requests.joinToString(), "UTF-8").contains("/oauth/token"))
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry("com.proteles.auth.$clientId")
    }
}
