plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.proteles.example"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.proteles.example"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = providers.gradleProperty("VERSION_NAME").get()

        // Point the example at a tenant with -PprotelesIssuer=… -PprotelesClientId=…
        // The client must be public (token_endpoint_auth_method "none"), have the
        // refresh_token grant, and register exactly these redirect URIs.
        val issuer = providers.gradleProperty("protelesIssuer").getOrElse("https://auth.example.com")
        val clientId = providers.gradleProperty("protelesClientId").getOrElse("com.proteles.example")
        // What "Call the API" sends the access token to: by default the issuer's
        // userinfo endpoint (as this server's discovery names it), which accepts
        // one; -PprotelesApiUrl=… for the app's own API.
        val apiUrl = providers.gradleProperty("protelesApiUrl").getOrElse("${issuer.removeSuffix("/")}/oauth/userinfo")
        buildConfigField("String", "PROTELES_ISSUER", "\"$issuer\"")
        buildConfigField("String", "PROTELES_CLIENT_ID", "\"$clientId\"")
        buildConfigField("String", "PROTELES_API_URL", "\"$apiUrl\"")
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    lint {
        abortOnError = true
    }
}

dependencies {
    implementation(project(":android"))
    // The app's own coroutine plumbing (Dispatchers.Main); the SDK does not need it.
    implementation(libs.kotlinx.coroutines.android)
}
