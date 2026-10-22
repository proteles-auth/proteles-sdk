package com.proteles.auth.android

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.net.Uri
import android.os.Build
import androidx.browser.customtabs.CustomTabsIntent
import androidx.browser.customtabs.CustomTabsService
import com.proteles.auth.BrowserHop
import com.proteles.auth.ProtelesException

/**
 * The browser hop on Android (docs/mobile-SDKs.md §10.2 step 3): a Custom Tab —
 * the user's own browser, with its cookies and password manager, in the app's
 * task. Never a WebView, which would let the app read the password as it is typed.
 *
 * Construct one per call with the Activity in front; `ProtelesClient.signIn(activity)`
 * does that for you.
 */
public class CustomTabsBrowserHop(private val activity: Activity) : BrowserHop {
    override suspend fun open(url: String, returnUri: String?): String {
        if (returnUri != null) RedirectActivity.checkDeclared(activity, returnUri)
        val flow = AuthorizationFlows.start(url)
        try {
            val start = AuthorizationActivity.startIntent(activity, flow.id)
            activity.runOnUiThread {
                try {
                    activity.startActivity(start)
                } catch (e: ActivityNotFoundException) {
                    flow.outcome.complete(
                        AuthorizationFlows.Outcome.Failed(
                            ProtelesException.Configuration("AuthorizationActivity is missing from the merged manifest", e),
                        ),
                    )
                }
            }
            return AuthorizationFlows.await(flow)
        } finally {
            AuthorizationFlows.finish(flow.id)
        }
    }
}

/**
 * Opens a URL in the system browser — always a browser package named
 * explicitly, so neither an app claiming the issuer's domain as an App Link nor
 * the chooser can take the sign-in page.
 */
internal object Browsers {
    fun open(activity: Activity, uri: Uri) {
        val pm = activity.packageManager
        val choice = choose(defaultBrowser(pm), installedBrowsers(pm)) { supportsCustomTabs(pm, it) }
            ?: throw ActivityNotFoundException("no browser is installed")
        when (choice) {
            is Choice.CustomTab -> {
                val tab = CustomTabsIntent.Builder().setShowTitle(true).build()
                tab.intent.setPackage(choice.packageName)
                tab.launchUrl(activity, uri)
            }
            is Choice.Plain -> activity.startActivity(
                Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE).setPackage(choice.packageName),
            )
        }
    }

    sealed class Choice {
        abstract val packageName: String

        /** A Custom Tab of this browser, in the app's task. */
        data class CustomTab(override val packageName: String) : Choice()

        /** This browser, in its own task: no installed browser offers Custom Tabs. */
        data class Plain(override val packageName: String) : Choice()
    }

    /**
     * Which browser shows the page (the AppAuth order): among the installed
     * [browsers], the default one first, the first that offers Custom Tabs;
     * failing that, the default browser, else the first one, in a plain VIEW.
     * Null when there is no browser. Never "whatever resolves the URL".
     */
    fun choose(defaultBrowser: String?, browsers: List<String>, supportsCustomTabs: (String) -> Boolean): Choice? {
        val ordered = (listOfNotNull(defaultBrowser?.takeIf { it in browsers }) + browsers).distinct()
        ordered.firstOrNull(supportsCustomTabs)?.let { return Choice.CustomTab(it) }
        return ordered.firstOrNull()?.let { Choice.Plain(it) }
    }

    /** A plain https link with no host: only a browser's filter matches it, never an App Link's. */
    private fun probe(): Intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://")).addCategory(Intent.CATEGORY_BROWSABLE)

    /**
     * Installed browsers: packages with an activity that takes VIEW for any https
     * URL — no host or path in its filter — with DEFAULT (so an implicit
     * startActivity reaches it) and BROWSABLE.
     */
    fun installedBrowsers(pm: PackageManager): List<String> {
        val flags = PackageManager.MATCH_DEFAULT_ONLY or PackageManager.GET_RESOLVED_FILTER
        val found: List<ResolveInfo> = if (Build.VERSION.SDK_INT >= 33) {
            pm.queryIntentActivities(probe(), PackageManager.ResolveInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.queryIntentActivities(probe(), flags)
        }
        return found.filter { isFullBrowser(it) }.mapNotNull { it.activityInfo?.packageName }.distinct()
    }

    private fun isFullBrowser(info: ResolveInfo): Boolean {
        val filter = info.filter ?: return false
        return filter.hasAction(Intent.ACTION_VIEW) &&
            filter.hasCategory(Intent.CATEGORY_BROWSABLE) &&
            filter.hasDataScheme("https") &&
            filter.countDataAuthorities() == 0 &&
            filter.countDataPaths() == 0
    }

    /** The package that handles a plain https link — the default browser — unless that is the chooser. */
    private fun defaultBrowser(pm: PackageManager): String? {
        val resolved = if (Build.VERSION.SDK_INT >= 33) {
            pm.resolveActivity(probe(), PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.resolveActivity(probe(), PackageManager.MATCH_DEFAULT_ONLY)
        }
        return resolved?.activityInfo?.packageName?.takeIf { it != "android" }
    }

    fun supportsCustomTabs(pm: PackageManager, packageName: String): Boolean {
        val service = Intent(CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION).setPackage(packageName)
        return if (Build.VERSION.SDK_INT >= 33) {
            pm.resolveService(service, PackageManager.ResolveInfoFlags.of(0L)) != null
        } else {
            @Suppress("DEPRECATION")
            pm.resolveService(service, 0) != null
        }
    }
}
