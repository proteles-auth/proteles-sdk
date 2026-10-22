package com.proteles.auth.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xml.sax.Attributes
import org.xml.sax.helpers.DefaultHandler
import java.io.File
import java.util.concurrent.TimeUnit
import javax.xml.parsers.SAXParserFactory

/**
 * `:core` is a plain JVM module, so Android Lint's NewApi check never sees it —
 * tried, and a positive control (an API-33 call planted in :core) went
 * unreported. This is that check done directly: every JDK/Android API the
 * compiled :core classes reference, as `javap` reports them, looked up in the
 * compile SDK's own API database (`platforms/<sdk>/data/api-versions.xml`) and
 * held to minSdk. A JDK API that Android does not have at all fails too.
 */
class CoreApiLevelTest {
    private val classesDir = File(System.getProperty("proteles.core.classes") ?: error("proteles.core.classes not set"))
    private val apiDatabase = File(System.getProperty("proteles.api.versions") ?: error("proteles.api.versions not set"))
    private val minSdk = (System.getProperty("proteles.minSdk") ?: error("proteles.minSdk not set")).toDouble()

    private class ApiClass(val since: Double, val supers: MutableList<String> = mutableListOf(), val members: MutableMap<String, Double> = HashMap())

    private val api: Map<String, ApiClass> by lazy {
        val classes = HashMap<String, ApiClass>()
        SAXParserFactory.newInstance().newSAXParser().parse(
            apiDatabase,
            object : DefaultHandler() {
                private var current: ApiClass? = null

                override fun startElement(uri: String?, localName: String?, qName: String, attributes: Attributes) {
                    val since = attributes.getValue("since")?.toDouble()
                    when (qName) {
                        "class" -> current = ApiClass(since ?: 1.0).also { classes[attributes.getValue("name")] = it }
                        "extends", "implements" -> current?.supers?.add(attributes.getValue("name"))
                        "method", "field" -> current?.let { c -> c.members[attributes.getValue("name")] = since ?: c.since }
                    }
                }

                override fun endElement(uri: String?, localName: String?, qName: String) {
                    if (qName == "class") current = null
                }
            },
        )
        classes
    }

    /** The API level at which [owner]'s [member] exists, walking supertypes; null when Android has no such API. */
    private fun sinceOf(owner: String, member: String?): Double? {
        val root = api[owner] ?: return null
        if (member == null) return root.since
        val seen = HashSet<String>()
        val queue = ArrayDeque(listOf(owner))
        while (queue.isNotEmpty()) {
            val name = queue.removeFirst()
            if (!seen.add(name)) continue
            val cls = api[name] ?: continue
            cls.members[member]?.let { return maxOf(it, root.since) }
            queue.addAll(cls.supers)
        }
        return api["java/lang/Object"]?.members?.get(member)?.let { maxOf(it, root.since) }
    }

    private data class Ref(val owner: String, val member: String?, val from: String)

    private val platformPrefixes = listOf("java/", "javax/", "android/", "dalvik/", "org/json/", "org/w3c/", "org/xml/")

    /** Every platform class, method and field the given class files reference. */
    private fun references(classFiles: List<File>): Set<Ref> {
        val javap = File(System.getProperty("java.home"), "bin/javap").path
        val process = ProcessBuilder(listOf(javap, "-c", "-p") + classFiles.map { it.path }).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        assertTrue("javap timed out", process.waitFor(120, TimeUnit.SECONDS))
        assertEquals("javap failed:\n${output.take(2000)}", 0, process.exitValue())
        val refs = HashSet<Ref>()
        var from = "?"
        val member = Regex("""// (?:Method|InterfaceMethod|Field) ([\w/$]+)\.("?[\w<>$]+"?):(\S+)""")
        val klass = Regex("""// class ([\w/$]+)\s*$""")
        for (line in output.lineSequence()) {
            if (line.startsWith("Compiled from") || line.matches(Regex("""^(public |final |abstract |synchronized )*(class|interface) .*"""))) {
                from = line.trim()
            }
            member.find(line)?.let { m ->
                val owner = m.groupValues[1]
                val name = m.groupValues[2].trim('"')
                val desc = m.groupValues[3]
                val key = if (line.contains("// Field")) name else name + desc
                refs.add(Ref(owner, key, from))
                refs.add(Ref(owner, null, from))
            }
            klass.find(line)?.let { refs.add(Ref(it.groupValues[1], null, from)) }
        }
        return refs.filter { r -> platformPrefixes.any { r.owner.startsWith(it) } }.toSet()
    }

    private fun violations(refs: Set<Ref>): List<String> = refs.mapNotNull { r ->
        val since = sinceOf(r.owner, r.member)
        val what = r.owner.replace('/', '.') + (r.member?.let { "#$it" } ?: "")
        when {
            since == null -> "$what is not in Android's API at all (from ${r.from})"
            since > minSdk -> "$what needs API ${since.toString().removeSuffix(".0")} > minSdk ${minSdk.toInt()} (from ${r.from})"
            else -> null
        }
    }.sorted()

    @Test
    fun `core uses only APIs that Android minSdk has`() {
        val classFiles = classesDir.walkTopDown().filter { it.isFile && it.extension == "class" }.toList()
        assertTrue("no compiled :core classes under $classesDir", classFiles.size >= 20)
        val refs = references(classFiles)
        // Sanity: the scan saw the platform APIs core is built on.
        for (expected in listOf("java/security/Signature", "java/util/Base64", "java/net/HttpURLConnection", "java/security/MessageDigest")) {
            assertTrue("the scan did not see $expected", refs.any { it.owner == expected })
        }
        val bad = violations(refs)
        assertTrue("APIs :core uses that Android $minSdk lacks:\n" + bad.joinToString("\n"), bad.isEmpty())
    }

    @Test
    fun `the check itself flags an API-33 method and an API Android lacks (positive control)`() {
        val planted = setOf(
            Ref("java/net/URLEncoder", "encode(Ljava/lang/String;Ljava/nio/charset/Charset;)Ljava/lang/String;", "control"),
            Ref("java/io/InputStream", "readAllBytes()[B", "control"),
            Ref("java/io/FileInputStream", "readAllBytes()[B", "control"), // inherited, found through the supertype walk
            Ref("java/net/http/HttpClient", null, "control"),
            Ref("java/util/Base64", "getUrlDecoder()Ljava/util/Base64\$Decoder;", "control"),
        )
        val bad = violations(planted)
        assertEquals(bad.joinToString("\n"), 4, bad.size)
        assertTrue(bad.any { it.startsWith("java.net.http.HttpClient is not in Android") })
        assertTrue(bad.none { it.startsWith("java.util.Base64") })
    }
}
