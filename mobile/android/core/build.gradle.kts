import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    alias(libs.plugins.kotlin.jvm)
    `maven-publish`
}

group = "com.proteles"
version = providers.gradleProperty("VERSION_NAME").get()
description = "The Proteles native SDK's protocol core: sign-in, refresh and sign-out " +
    "for a public OAuth 2.0 / OpenID Connect client, in plain Kotlin/JVM."

// Bytecode an Android app of any current AGP can dex, and a JVM of 11 or later
// can run. Every JDK API used here also exists on Android API 26 (the :android
// minSdk) — see README "Dependencies".
java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
    withSourcesJar()
}

kotlin {
    // A library: nothing becomes public API by forgetting a modifier.
    explicitApi()
    coreLibrariesVersion = "2.2.10"
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
        // Built with Kotlin 2.4 but emitting 2.2 metadata against the 2.2 stdlib
        // API (and depending on stdlib 2.2.10, see coreLibrariesVersion), so an
        // app need not be on 2.4 to consume it. 2.2 is the oldest level 2.4 does
        // not deprecate. Consumption by an older-Kotlin app is not tested here.
        languageVersion.set(KotlinVersion.KOTLIN_2_2)
        apiVersion.set(KotlinVersion.KOTLIN_2_2)
        // -Pwerror=false exists for mutation testing, where a mutant that the
        // compiler can see through (an always-false condition) must still build.
        allWarningsAsErrors.set(providers.gradleProperty("werror").map { it.toBoolean() }.orElse(true))
    }
}

dependencies {
    // Mutex (single-flight refresh, JWKS dedupe) and Dispatchers.IO. The only
    // third-party runtime dependency; everything cryptographic is java.security.
    implementation(libs.kotlinx.coroutines.core)

    testImplementation(kotlin("test"))
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

// The shared vectors are read from the repository at test time — never copied.
// Declared as an input so a changed vectors.json or reference-verify.mjs makes
// `:core:test` run again instead of reporting UP-TO-DATE.
val vectorsDir = layout.projectDirectory.dir("../../vectors")

tasks.test {
    useJUnitPlatform()
    inputs.dir(vectorsDir).withPropertyName("sharedVectors").withPathSensitivity(PathSensitivity.RELATIVE)
    systemProperty("proteles.vectors.dir", vectorsDir.asFile.absolutePath)
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

// The live suite (docs/mobile-SDKs.md §10.8): the real ProtelesClient against a
// real Proteles server, which mobile/live/run-live.sh starts, seeds and
// describes in PROTELES_LIVE_* variables. From the repository root:
//
//   mobile/live/run-live.sh -- mobile/android/gradlew -p mobile/android :core:liveTest
//
// Its own source set and task, so `:core:test` never needs a server; without
// PROTELES_LIVE_ISSUER the task is skipped and says why. The source set is not
// associated with main, so it sees only :core's public API — as an app does.
val liveTest: SourceSet = sourceSets.create("liveTest") {
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
}
configurations[liveTest.implementationConfigurationName].extendsFrom(
    configurations.implementation.get(),
    configurations.testImplementation.get(),
)
configurations[liveTest.runtimeOnlyConfigurationName].extendsFrom(
    configurations.runtimeOnly.get(),
    configurations.testRuntimeOnly.get(),
)

// Compiled whenever the unit tests are, so a change to the public API that
// breaks the live suite fails `:core:test` in CI rather than surfacing only
// when somebody next starts a server.
tasks.named("testClasses") { dependsOn(liveTest.classesTaskName) }

val liveVariables = listOf(
    "PROTELES_LIVE_ISSUER",
    "PROTELES_LIVE_CLIENT_ID",
    "PROTELES_LIVE_REDIRECT_URI",
    "PROTELES_LIVE_POST_LOGOUT_REDIRECT_URI",
    "PROTELES_LIVE_USERNAME",
    "PROTELES_LIVE_PASSWORD",
)
val liveIssuer = providers.environmentVariable("PROTELES_LIVE_ISSUER")

tasks.register<Test>("liveTest") {
    description = "Runs the SDK against a real server started by mobile/live/run-live.sh (skipped without PROTELES_LIVE_ISSUER)."
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    testClassesDirs = liveTest.output.classesDirs
    classpath = liveTest.runtimeClasspath
    useJUnitPlatform()
    onlyIf("PROTELES_LIVE_ISSUER is set (run it under mobile/live/run-live.sh)") { liveIssuer.isPresent }
    // The server is not an input Gradle can see: each run meets a new one, so a
    // result is never up to date and never taken from the build cache.
    outputs.upToDateWhen { false }
    outputs.cacheIf { false }
    // Passed on by name, so a Gradle daemon started before run-live.sh still
    // hands the test this run's server rather than its own environment's.
    for (name in liveVariables) providers.environmentVariable(name).orNull?.let { environment(name, it) }
    testLogging {
        events("passed", "skipped", "failed")
        // Each step prints what the server answered (never a token or the password).
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

// `./gradlew publishAllPublicationsToBuildRepository` writes a Maven repository to
// build/repo that an app can point at; see the README. The POM's shared half, the
// javadoc jar, the signature and the repositories are added by the root
// build.gradle.kts, the same for :android.
publishing {
    publications {
        create<MavenPublication>("release") {
            from(components["java"])
            artifactId = "proteles-auth-core"
            pom {
                name.set("Proteles Auth Core")
                description.set(project.description)
            }
        }
    }
}
