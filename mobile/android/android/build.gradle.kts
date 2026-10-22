import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    // AGP 9 compiles Kotlin itself: no org.jetbrains.kotlin.android here.
    alias(libs.plugins.android.library)
    `maven-publish`
}

group = "com.proteles"
version = providers.gradleProperty("VERSION_NAME").get()
description = "Proteles sign-in for Android: the system browser (a Custom Tab), " +
    "Keystore-sealed storage and a cross-process refresh lock, around proteles-auth-core."

android {
    namespace = "com.proteles.auth.android"
    // The installed platform is android-37.0; AGP 9.3.2 builds against it.
    compileSdk = 37

    defaultConfig {
        // Android 8.0: java.util.Base64, java.nio.file and java.time are all
        // present, and the Keystore has had AES-GCM keys since API 23.
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    testOptions {
        // JVM unit tests (the file lock, the sealed store format) touch no
        // Android API; any stray call returns a default instead of throwing.
        unitTests.isReturnDefaultValues = true
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

kotlin {
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
        allWarningsAsErrors.set(providers.gradleProperty("werror").map { it.toBoolean() }.orElse(true))
    }
}

dependencies {
    // Every protocol rule lives in :core; this module is the platform around it.
    api(project(":core"))
    // Custom Tabs: the system browser in the app's task (never a WebView).
    implementation(libs.androidx.browser)
    implementation(libs.kotlinx.coroutines.core)

    testImplementation(libs.junit4)

    // `./gradlew :android:connectedDebugAndroidTest` on an emulator or device:
    // the real Keystore, and the browser hop through a real Custom Tab.
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.junit4)
}

// See :core: the root build.gradle.kts adds the rest to this publication too.
afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                artifactId = "proteles-auth-android"
                pom {
                    name.set("Proteles Auth for Android")
                    description.set(project.description)
                }
            }
        }
    }
}

// CoreApiLevelTest: :core's compiled classes, held to minSdk through the compile
// SDK's own API database. Lint cannot do this for a plain JVM module.
val coreClasses = project(":core").layout.buildDirectory.dir("classes/kotlin/main")
tasks.withType<Test>().configureEach {
    dependsOn(":core:compileKotlin")
    inputs.dir(coreClasses).withPropertyName("coreClasses").withPathSensitivity(PathSensitivity.RELATIVE)
    val sdkDir = androidComponents.sdkComponents.sdkDirectory.get().asFile
    val platform = sdkDir.resolve("platforms").listFiles()
        ?.filter { it.name == "android-${android.compileSdk}" || it.name.startsWith("android-${android.compileSdk}.") }
        ?.maxByOrNull { it.name }
    val apiVersions = platform?.resolve("data/api-versions.xml")
    systemProperty("proteles.core.classes", coreClasses.get().asFile.absolutePath)
    systemProperty("proteles.api.versions", apiVersions?.absolutePath ?: "missing: no platform for compileSdk ${android.compileSdk}")
    systemProperty("proteles.minSdk", android.defaultConfig.minSdk.toString())
    // ExampleAppTest scans the example app's sources: an input, so an edit there reruns it.
    val exampleSources = layout.projectDirectory.dir("../example/src/main/kotlin")
    inputs.dir(exampleSources).withPropertyName("exampleSources").withPathSensitivity(PathSensitivity.RELATIVE)
    systemProperty("proteles.example.sources", exampleSources.asFile.absolutePath)
}
