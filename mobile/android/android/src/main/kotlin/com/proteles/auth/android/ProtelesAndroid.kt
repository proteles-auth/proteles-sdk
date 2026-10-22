package com.proteles.auth.android

import android.app.Activity
import android.content.Context
import com.proteles.auth.IdTokenClaims
import com.proteles.auth.ProtelesClient
import com.proteles.auth.ProtelesConfiguration
import com.proteles.auth.ProtelesException
import com.proteles.auth.SignOutResult

/** Builds the Android [ProtelesClient]: Keystore-backed storage and the cross-process file lock. */
public object ProtelesAndroid {
    private val clients = HashMap<String, ProtelesClient>()

    /**
     * The client for [configuration] — one per configuration per process, so every
     * caller shares one discovery cache, one key-set cache and one refresh mutex.
     *
     * @throws ProtelesException.Configuration for a redirect URI Android cannot receive.
     */
    @JvmStatic
    public fun client(context: Context, configuration: ProtelesConfiguration): ProtelesClient {
        checkRedirectsForAndroid(configuration)
        val app = context.applicationContext
        synchronized(clients) {
            return clients.getOrPut(configuration.toString()) {
                ProtelesClient(
                    configuration = configuration,
                    store = KeystoreTokenStore.create(app, configuration.clientId),
                    crossProcessLock = FileCrossProcessLock.forClient(app, configuration.clientId),
                )
            }
        }
    }

    /**
     * What §10.1 allows but Android cannot deliver: capitals in the scheme or
     * the host. Android matches intent filters' schemes and hosts
     * case-sensitively, and browsers lower-case both before they navigate, so
     * `HTTPS://App.Example.com/cb` would never reach the app's filter.
     * (Loopback `http:` redirects and private-use schemes, which Android cannot
     * or may not receive, are refused by the configuration itself: §10.1
     * and M7.)
     */
    internal fun checkRedirectsForAndroid(configuration: ProtelesConfiguration) {
        for (uri in listOfNotNull(configuration.redirectUri, configuration.postLogoutRedirectUri)) {
            val parsed = java.net.URI(uri)
            val scheme = parsed.scheme.orEmpty()
            val host = parsed.host.orEmpty()
            if (scheme != scheme.lowercase() || host != host.lowercase()) {
                throw ProtelesException.Configuration(
                    "$uri: write the scheme and host in lower case — Android matches intent filters case-sensitively and browsers lower-case them",
                )
            }
        }
    }
}

/**
 * Signs in through a Custom Tab (docs/mobile-SDKs.md §10.2). Call from the
 * Activity in front; suspends until the user finishes in the browser.
 *
 * @throws ProtelesException.Cancelled when the user closes the browser.
 * @throws ProtelesException.AlreadyInProgress while another sign-in is showing
 *   (a double tap; nothing was done).
 * @throws ProtelesException.BrowserUnavailable when no browser can show the page.
 */
public suspend fun ProtelesClient.signIn(activity: Activity): IdTokenClaims = signIn(CustomTabsBrowserHop(activity))

/**
 * Signs out (docs/mobile-SDKs.md §10.4, §10.9 item 6): clears the store, then
 * revokes the refresh token, whatever happens to either. With [endSession], the
 * browser is then sent to the issuer's end-session endpoint to end the browser
 * session too — only from a user gesture, since it puts a browser page in front
 * of the user.
 *
 * @throws ProtelesException.AlreadyInProgress with [endSession], while a sign-in
 *   is showing the browser (nothing was done).
 * @throws ProtelesException.Storage when the store could not be cleared (the
 *   refresh token was revoked all the same).
 */
public suspend fun ProtelesClient.signOut(activity: Activity, endSession: Boolean): SignOutResult =
    signOut(if (endSession) CustomTabsBrowserHop(activity) else null)
