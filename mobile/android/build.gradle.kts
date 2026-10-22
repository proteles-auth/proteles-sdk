import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.plugins.signing.SigningExtension

plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    // Declared here so one Kotlin Gradle plugin version serves :core and the
    // Kotlin that AGP 9 compiles for :android and :example.
    alias(libs.plugins.kotlin.jvm) apply false
}

// What every published artifact carries, written once for :core and :android:
// the half of the POM that describes the project rather than the module, a
// javadoc jar, a signature when there is a key, and the one repository. Each
// module creates its own publication — :android only in afterEvaluate, once AGP
// has made its component — so this reaches publications through configureEach,
// which also sees the ones made later.
subprojects {
    pluginManager.withPlugin("maven-publish") {
        val publishing = extensions.getByType<PublishingExtension>()
        val pomProperty = { key: String -> providers.gradleProperty(key) }

        // The README as a released version carries it. Central keeps a version
        // for good, so the copy in its javadoc jar holds only what stays true of
        // that version: everything from "## For contributors" on is dropped (it
        // points into this repository, and records questions still open), and
        // so is each block between an `<!-- unpublished … -->` line and
        // `<!-- /unpublished -->` — the note that it is not on Central yet, and
        // the ways to install it without Central. scripts/publish-readiness.mjs
        // reads this file back out of the jar.
        val readme = rootProject.layout.projectDirectory.file("README.md")
        val publishedReadme = layout.buildDirectory.file("published-readme/README.md")
        val publishedReadmeTask = tasks.register("publishedReadme") {
            description = "The README with its contributors' part and unpublished blocks removed, for the javadoc jar."
            inputs.file(readme)
            outputs.file(publishedReadme)
            doLast {
                val kept = StringBuilder()
                var dropping = false
                for ((i, line) in readme.asFile.readLines().withIndex()) {
                    val t = line.trim()
                    if (t == "## For contributors") break
                    if (t.startsWith("<!-- unpublished")) {
                        check(!dropping) { "README.md:${i + 1}: an unpublished block opens inside another" }
                        dropping = true
                        continue
                    }
                    if (t == "<!-- /unpublished -->") {
                        check(dropping) { "README.md:${i + 1}: an unpublished block closes that never opened" }
                        dropping = false
                        continue
                    }
                    if (!dropping) kept.append(line).append('\n')
                }
                check(!dropping) { "README.md: an unpublished block is never closed" }
                val out = publishedReadme.get().asFile
                out.parentFile.mkdirs()
                out.writeText(kept.toString().replace(Regex("\n{3,}"), "\n\n").trimEnd() + "\n")
            }
        }

        // Maven Central requires a javadoc jar beside every jar it takes, and
        // accepts one holding a README for code that has no Javadoc. This code
        // is Kotlin, whose API documentation would come from Dokka, a plugin
        // (and, through AGP's own withJavadocJar, a toolchain) this build
        // otherwise does without. The README is where the API is documented.
        val javadocJar = tasks.register<Jar>("readmeJavadocJar") {
            description = "A javadoc jar holding the README, which Maven Central accepts for code without Javadoc."
            archiveClassifier.set("javadoc")
            from(publishedReadmeTask)
        }

        publishing.publications.withType<MavenPublication>().configureEach {
            artifact(javadocJar)
            // Each module names and describes itself; the rest is the project's.
            // The developer's address is a placeholder until a maintainer
            // fills it in: see gradle.properties.
            pom {
                url.set(pomProperty("POM_URL"))
                licenses {
                    license {
                        // The repository's licence; its text is LICENSE, here.
                        name.set("MIT License")
                        url.set("https://opensource.org/license/mit")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        id.set(pomProperty("POM_DEVELOPER_ID"))
                        name.set(pomProperty("POM_DEVELOPER_NAME"))
                        email.set(pomProperty("POM_DEVELOPER_EMAIL"))
                    }
                }
                scm {
                    url.set(pomProperty("POM_SCM_URL"))
                    connection.set(pomProperty("POM_SCM_CONNECTION"))
                    developerConnection.set(pomProperty("POM_SCM_DEV_CONNECTION"))
                }
            }
        }

        publishing.repositories {
            // A Maven repository in build/repo, which an app can point at (see
            // the README) and which a release zips for Maven Central.
            maven {
                name = "build"
                url = uri(rootProject.layout.buildDirectory.dir("repo"))
            }
        }

        // Signed only when a key is supplied, as the ASCII-armoured secret key
        // in the signingInMemoryKey property (ORG_GRADLE_PROJECT_signingInMemoryKey
        // in the environment) and its passphrase in signingInMemoryKeyPassword.
        // Without one the signing plugin is not even applied, so a local build
        // or publish needs no key and makes no .asc; Maven Central refuses an
        // unsigned upload, so a release cannot slip through unsigned either.
        val signingKey = providers.gradleProperty("signingInMemoryKey")
        if (signingKey.isPresent) {
            apply(plugin = "signing")
            val signing = extensions.getByType<SigningExtension>()
            signing.useInMemoryPgpKeys(
                signingKey.get(),
                providers.gradleProperty("signingInMemoryKeyPassword").getOrElse(""),
            )
            publishing.publications.withType<MavenPublication>().configureEach {
                signing.sign(this)
            }
        }
    }
}
