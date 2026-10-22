package com.proteles.example

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URI

/**
 * Calls the app's API with [accessToken] and returns only the HTTP status. The
 * token goes into the `Authorization` header and nowhere else — never on
 * screen, never in a log — so pass `validAccessToken()` straight in: ask for it
 * before every request, and never keep it.
 */
internal suspend fun callApi(url: String, accessToken: String): Int = withContext(Dispatchers.IO) {
    val connection = URI(url).toURL().openConnection() as HttpURLConnection
    try {
        // A redirect would re-send the bearer token to wherever it points.
        connection.instanceFollowRedirects = false
        connection.setRequestProperty("Authorization", "Bearer $accessToken")
        connection.responseCode
    } finally {
        connection.disconnect()
    }
}
