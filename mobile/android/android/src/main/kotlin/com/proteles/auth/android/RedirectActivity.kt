package com.proteles.auth.android

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.net.Uri
import android.os.Build
import android.os.Bundle
import com.proteles.auth.ProtelesException

/**
 * Receives the browser's redirect to the app's redirect URI and hands it to the
 * waiting sign-in. **The app declares this activity in its own manifest**, with
 * a verified App Link intent filter for its redirect's host and path. The
 * redirect is an `https` URL: the server registers no private-use scheme (M7).
 *
 * ```xml
 * <activity
 *     android:name="com.proteles.auth.android.RedirectActivity"
 *     android:exported="true"
 *     android:theme="@android:style/Theme.Translucent.NoTitleBar">
 *     <intent-filter android:autoVerify="true">
 *         <action android:name="android.intent.action.VIEW" />
 *         <category android:name="android.intent.category.DEFAULT" />
 *         <category android:name="android.intent.category.BROWSABLE" />
 *         <data android:scheme="https" android:host="app.example.com" android:path="/oauth/callback" />
 *     </intent-filter>
 * </activity>
 * ```
 *
 * `autoVerify` has Android check the domain's `assetlinks.json` names the app,
 * which is what makes the link go to this app and no other.
 *
 * It is exported — the browser must be able to start it — so anything on the
 * device can send it a URI. That is safe because it only forwards: the
 * callback is then held to the `state` this request sent and the issuer's `iss`
 * before anything is exchanged.
 */
public class RedirectActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        intent?.data?.let { startActivity(AuthorizationActivity.redirectIntent(this, it)) }
        finish()
    }

    internal companion object {
        /**
         * Refuses, before the browser opens, a redirect URI this app has not routed
         * to [RedirectActivity] — otherwise the browser would land somewhere the SDK
         * never hears about and the sign-in would wait forever.
         */
        fun checkDeclared(context: Context, returnUri: String) {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(returnUri))
                .addCategory(Intent.CATEGORY_BROWSABLE)
                .setPackage(context.packageName)
            // MATCH_DEFAULT_ONLY: the browser delivers the redirect with an implicit
            // startActivity, which only reaches a filter that names
            // android.intent.category.DEFAULT. A filter without it would pass a
            // plain query and still never receive the redirect.
            val matches: List<ResolveInfo> = if (Build.VERSION.SDK_INT >= 33) {
                context.packageManager.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY.toLong()))
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY)
            }
            if (matches.none { it.activityInfo?.name == RedirectActivity::class.java.name }) {
                throw ProtelesException.Configuration(
                    "no activity handles $returnUri: declare com.proteles.auth.android.RedirectActivity in the app " +
                        "manifest with a VIEW intent filter (autoVerify), categories DEFAULT and BROWSABLE, for " +
                        "https://${Uri.parse(returnUri).host}${Uri.parse(returnUri).path.orEmpty()} (see the README)",
                )
            }
        }
    }
}
