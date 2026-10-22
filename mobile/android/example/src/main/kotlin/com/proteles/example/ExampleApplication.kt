package com.proteles.example

import android.app.Application
import com.proteles.auth.ProtelesClient
import com.proteles.auth.ProtelesConfiguration
import com.proteles.auth.android.ProtelesAndroid
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.MainScope

/**
 * Holds what must outlive an Activity: the client (one per process) and the
 * scope sign-in runs in.
 *
 * Not an Activity's scope: a rotation, a dark-mode switch or unfolding the
 * device while the Custom Tab is in front recreates the Activity, and a sign-in
 * running in the old Activity's scope would be cancelled just as the user comes
 * back from the browser. An app with androidx.lifecycle uses `viewModelScope`
 * for the same reason.
 */
class ExampleApplication : Application() {
    lateinit var client: ProtelesClient
        private set

    val scope: CoroutineScope = MainScope()

    /** The last thing that happened, for whichever MainActivity is showing. */
    var status: String = ""
        set(value) {
            field = value
            onStatus?.invoke(value)
        }

    var onStatus: ((String) -> Unit)? = null

    override fun onCreate() {
        super.onCreate()
        client = ProtelesAndroid.client(
            this,
            ProtelesConfiguration(
                issuer = BuildConfig.PROTELES_ISSUER,
                clientId = BuildConfig.PROTELES_CLIENT_ID,
                redirectUri = "https://app.example.com/oauth/callback",
                postLogoutRedirectUri = "https://app.example.com/oauth/signed-out",
            ),
        )
    }
}
