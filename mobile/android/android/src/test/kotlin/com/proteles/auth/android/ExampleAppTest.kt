package com.proteles.auth.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The example app (docs/mobile-SDKs.md §10.8) is what an integrator copies, and
 * the SDK promises its messages never contain a token: the example must not
 * put one on screen either. It has no JVM tests of its own, so its sources are
 * scanned here — with a positive control for each rule, so a scan that reads
 * nothing cannot pass.
 */
class ExampleAppTest {
    private val sources = File(System.getProperty("proteles.example.sources") ?: "../example/src/main/kotlin")

    private class Line(val where: String, val text: String)

    /** Every line of code in the example's Kotlin sources; comments say what code does, and are not scanned. */
    private val lines: List<Line> by lazy {
        sources.walkTopDown().filter { it.isFile && it.extension == "kt" }.flatMap { file ->
            file.readLines().mapIndexed { i, text -> Line("${file.name}:${i + 1}", text) }.asSequence()
        }.filterNot { line -> line.text.trim().let { it.startsWith("*") || it.startsWith("/*") || it.startsWith("//") } }.toList()
    }

    @Test
    fun `every access token the example asks for goes straight into an API request`() {
        val asks = lines.filter { "validAccessToken(" in it.text }
        assertTrue("the scan found no validAccessToken() call under $sources", asks.isNotEmpty())
        val handedStraightOver = Regex("""callApi\([^()]*,\s*app\.client\.validAccessToken\(\)\)""")
        for (ask in asks) {
            assertTrue("${ask.where}: pass the token straight to callApi — never keep it or show it: ${ask.text.trim()}", handedStraightOver.containsMatchIn(ask.text))
        }
    }

    @Test
    fun `no string the example builds interpolates a token, but the Authorization header`() {
        val interpolatesAToken = Regex("\\$\\{?[A-Za-z_.]*[Tt]oken")
        val found = lines.filter { interpolatesAToken.containsMatchIn(it.text) }
        val header = found.filter { "\"Authorization\", \"Bearer \$accessToken\"" in it.text }
        assertEquals("the scan must see the one place a token belongs: $found", 1, header.size)
        assertEquals("a token interpolated into a string: ${found.map { "${it.where}: ${it.text.trim()}" }}", header, found)
    }
}
