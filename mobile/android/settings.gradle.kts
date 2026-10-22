pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "proteles-android"

// Every protocol rule, on the JVM: `./gradlew :core:test`.
include(":core")
// The Android library: Custom Tabs, the redirect activity, Keystore storage and
// the cross-process lock.
include(":android")
// A minimal app that consumes :android the way a customer would, so the README's
// manifest entry is proven by a manifest merge rather than by being read.
include(":example")
