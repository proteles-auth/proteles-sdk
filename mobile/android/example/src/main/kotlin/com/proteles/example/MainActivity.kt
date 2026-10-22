package com.proteles.example

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import com.proteles.auth.IdTokenClaims
import com.proteles.auth.ProtelesException
import com.proteles.auth.SignOutResult
import com.proteles.auth.android.signIn
import com.proteles.auth.android.signOut
import kotlinx.coroutines.launch
import java.io.IOException

/**
 * Sign in, call an API with the access token, sign out — the whole SDK surface
 * on one screen. The token itself is never shown: only the API's answer is.
 * The work runs in [ExampleApplication.scope], so it survives this Activity
 * being recreated while the browser is in front.
 */
class MainActivity : Activity() {
    private val app: ExampleApplication get() = application as ExampleApplication
    private lateinit var status: TextView
    private val showStatus: (String) -> Unit = { status.text = it }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        status = TextView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            // targetSdk 35+ draws edge to edge: keep the buttons clear of the status bar.
            fitsSystemWindows = true
            setPadding(48, 48, 48, 48)
            addView(TextView(this@MainActivity).apply { text = "Proteles example"; textSize = 22f })
            addView(button("Sign in") { signIn() })
            addView(button("Call the API") { useToken() })
            addView(button("Sign out") { signOut(endSession = false) })
            addView(button("Sign out and end the browser session") { signOut(endSession = true) })
            addView(status)
        }
        setContentView(layout)
        app.onStatus = showStatus
        if (app.status.isEmpty()) {
            app.scope.launch {
                app.status = app.client.currentClaims()?.let { "Signed in as ${displayName(it)}" } ?: "Signed out"
            }
        } else {
            status.text = app.status
        }
    }

    override fun onDestroy() {
        if (app.onStatus === showStatus) app.onStatus = null
        super.onDestroy()
    }

    private fun button(label: String, onClick: () -> Unit) = Button(this).apply {
        text = label
        setOnClickListener { onClick() }
    }

    private fun signIn() {
        val activity = this // used only to open the browser; the call itself outlives it
        app.scope.launch {
            app.status = try {
                val claims = app.client.signIn(activity)
                "Signed in as ${displayName(claims)}"
            } catch (e: ProtelesException.AlreadyInProgress) {
                return@launch // a double tap: the sign-in already showing carries on
            } catch (e: ProtelesException.Cancelled) {
                "Sign-in cancelled"
            } catch (e: ProtelesException) {
                "Sign-in failed: ${e.javaClass.simpleName}"
            }
        }
    }

    private fun useToken() = app.scope.launch {
        app.status = try {
            // A fresh token for every request, handed straight to it: never kept, never shown.
            "The API answered HTTP ${callApi(BuildConfig.PROTELES_API_URL, app.client.validAccessToken())}"
        } catch (e: ProtelesException.SignInRequired) {
            "Sign in first"
        } catch (e: ProtelesException.RateLimited) {
            "Rate limited; retry in ${e.retryAfterSeconds ?: "a few"}s"
        } catch (e: ProtelesException) {
            "Could not get a token: ${e.javaClass.simpleName}"
        } catch (e: IOException) {
            "Could not reach the API: ${e.javaClass.simpleName}"
        }
    }

    /** As the iOS example shows the user: email, else preferred_username, else sub. */
    private fun displayName(claims: IdTokenClaims): String = claims.email ?: claims.preferredUsername ?: claims.subject

    private fun signOut(endSession: Boolean) {
        val activity = this
        app.scope.launch {
            val result = try {
                app.client.signOut(activity, endSession)
            } catch (e: ProtelesException.AlreadyInProgress) {
                return@launch // a sign-in or end-session is already showing the browser
            } catch (e: ProtelesException.Storage) {
                // The token was revoked, but this device could not delete its copy.
                app.status = "Sign-out could not clear this device's storage; try again"
                return@launch
            }
            val revoked = when (result.revocation) {
                is SignOutResult.Revocation.Failed -> "signed out here; the server was not told"
                else -> "signed out"
            }
            app.status = revoked + if (result.endSession == SignOutResult.EndSession.Completed) ", browser session ended" else ""
        }
    }
}
