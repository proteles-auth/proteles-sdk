package com.proteles.auth.android

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import com.proteles.auth.ProtelesException
import kotlinx.coroutines.CompletableDeferred
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * The requests currently in the browser, by id. Process memory only: if the OS
 * kills the app while the browser is in front, the suspended sign-in died with
 * it, and the redirect that later arrives finds nothing waiting (see the README,
 * "What it does not do").
 */
internal object AuthorizationFlows {
    sealed class Outcome {
        class Redirect(val uri: String) : Outcome()
        object Dismissed : Outcome()
        class Failed(val error: ProtelesException) : Outcome()
    }

    class Flow(val id: String, val url: String) {
        val outcome: CompletableDeferred<Outcome> = CompletableDeferred()
    }

    private val flows = ConcurrentHashMap<String, Flow>()

    fun start(url: String): Flow = Flow(UUID.randomUUID().toString(), url).also { flows[it.id] = it }

    fun get(id: String): Flow? = flows[id]

    fun finish(id: String) {
        flows.remove(id)
    }

    /**
     * Opens the browser for [flow] with [open]. When no browser can take it, the
     * flow fails with [ProtelesException.BrowserUnavailable] (§10.7) and this
     * returns false.
     */
    fun launch(flow: Flow, open: () -> Unit): Boolean = try {
        open()
        true
    } catch (e: ActivityNotFoundException) {
        flow.outcome.complete(Outcome.Failed(ProtelesException.BrowserUnavailable("no browser can show the sign-in page", e)))
        false
    } catch (e: SecurityException) {
        flow.outcome.complete(Outcome.Failed(ProtelesException.BrowserUnavailable("the browser refused to be started", e)))
        false
    }

    /** What the browser hop returns for [flow]: the redirect URI, or the error its outcome is. */
    suspend fun await(flow: Flow): String = when (val outcome = flow.outcome.await()) {
        is Outcome.Redirect -> outcome.uri
        Outcome.Dismissed -> throw ProtelesException.Cancelled()
        is Outcome.Failed -> throw outcome.error
    }
}

/**
 * Holds one browser request (sign-in or end-session) in the app's task — the
 * AppAuth pattern. It opens the Custom Tab on its first resume; the redirect
 * comes back through [RedirectActivity], which brings this activity to the front
 * with the redirect URI (clearing the Custom Tab above it). Resumed with no
 * redirect after the browser was opened means the user closed the browser.
 *
 * Declared by the library's manifest, not exported. Not for apps to start.
 */
internal class AuthorizationActivity : Activity() {
    private var flowId: String? = null
    private var browserOpened = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) {
            flowId = savedInstanceState.getString(STATE_FLOW)
            browserOpened = savedInstanceState.getBoolean(STATE_BROWSER_OPENED)
        } else {
            flowId = intent.getStringExtra(EXTRA_FLOW)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val newFlow = intent.getStringExtra(EXTRA_FLOW)
        if (newFlow != null && newFlow != flowId) {
            // A new request replaced one still in the browser: that one was abandoned.
            flowId?.let { AuthorizationFlows.get(it)?.outcome?.complete(AuthorizationFlows.Outcome.Dismissed) }
            flowId = newFlow
            browserOpened = false
        }
        setIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        val flow = flowId?.let { AuthorizationFlows.get(it) }
        if (flow == null) {
            // Nobody is waiting: the caller gave up, or the process was restarted.
            finish()
            return
        }
        val redirect = intent.data
        when {
            redirect != null -> {
                flow.outcome.complete(AuthorizationFlows.Outcome.Redirect(redirect.toString()))
                finish()
            }
            !browserOpened -> {
                browserOpened = true
                if (!AuthorizationFlows.launch(flow) { Browsers.open(this, Uri.parse(flow.url)) }) finish()
            }
            else -> {
                // Back in front without a redirect: the user closed the browser.
                flow.outcome.complete(AuthorizationFlows.Outcome.Dismissed)
                finish()
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(STATE_FLOW, flowId)
        outState.putBoolean(STATE_BROWSER_OPENED, browserOpened)
    }

    internal companion object {
        private const val EXTRA_FLOW = "com.proteles.auth.android.FLOW"
        private const val STATE_FLOW = "flow"
        private const val STATE_BROWSER_OPENED = "browserOpened"

        fun startIntent(context: Context, flowId: String): Intent =
            Intent(context, AuthorizationActivity::class.java).putExtra(EXTRA_FLOW, flowId)

        /** From [RedirectActivity]: back to the waiting instance, clearing the browser above it. */
        fun redirectIntent(context: Context, redirect: Uri): Intent =
            Intent(context, AuthorizationActivity::class.java)
                .setData(redirect)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
    }
}
