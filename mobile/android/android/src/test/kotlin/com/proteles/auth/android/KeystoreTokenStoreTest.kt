package com.proteles.auth.android

import com.proteles.auth.CrossProcessLock
import com.proteles.auth.ProtelesClient
import com.proteles.auth.ProtelesConfiguration
import com.proteles.auth.ProtelesException
import com.proteles.auth.StoredSession
import com.proteles.auth.UnreadableSessionException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * The sealed store's file handling and format on the JVM, with a software AES
 * key standing in for the Android Keystore one (the Keystore itself needs a
 * device; see the README's test section).
 */
class KeystoreTokenStoreTest {
    @get:Rule
    val temp = TemporaryFolder()

    private class SoftwareKey : KeySource {
        var key: SecretKey? = null
        override fun existing(): SecretKey? = key
        override fun getOrCreate(): SecretKey = key ?: KeyGenerator.getInstance("AES").apply { init(256) }.generateKey().also { key = it }
    }

    private val sample: StoredSession = StoredSession.decode(
        """{"v":1,"issuer":"https://auth.example.test","clientId":"com.example.app","accessToken":"at-1","obtainedAt":1800000000,"expiresAt":1800000900,"refreshToken":"rt-1","idToken":"h.p.s","claims":"{\"sub\":\"user-1\"}","scope":"openid"}"""
            .toByteArray(),
    )

    private fun store(file: File, keys: KeySource, aad: String = "com.proteles.auth.com.example.app") =
        KeystoreTokenStore(file, AesGcmSessionCipher(keys, aad.toByteArray()))

    /** A record that is there but can never be read (§10.9 item 6): not "nothing stored", and not a transient failure. */
    private fun assertUnreadable(store: KeystoreTokenStore) = runBlocking {
        try {
            store.read()
            fail("read an unreadable record")
        } catch (e: UnreadableSessionException) {
            // expected
        }
    }

    @Test
    fun `a session round-trips and is not stored in the clear`(): Unit = runBlocking {
        val file = File(temp.root, "s.session")
        val keys = SoftwareKey()
        store(file, keys).write(sample)
        val onDisk = file.readBytes()
        val text = String(onDisk, Charsets.ISO_8859_1)
        for (secret in listOf("at-1", "rt-1", "user-1", "h.p.s")) assertFalse("$secret on disk", text.contains(secret))
        assertEquals(1.toByte(), onDisk[0])
        val back = store(file, keys).read()!!
        assertArrayEquals(sample.encode(), back.encode())
        assertEquals("user-1", back.subject)
    }

    @Test
    fun `nothing stored reads as nobody signed in`(): Unit = runBlocking {
        assertNull(store(File(temp.root, "none.session"), SoftwareKey()).read())
    }

    @Test
    fun `a tampered record is unreadable, and the next write replaces it`(): Unit = runBlocking {
        val file = File(temp.root, "s.session")
        val keys = SoftwareKey()
        store(file, keys).write(sample)
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        file.writeBytes(bytes)
        assertUnreadable(store(file, keys))
        store(file, keys).write(sample)
        assertNotNull(store(file, keys).read())
    }

    @Test
    fun `a record sealed for another client cannot be opened`(): Unit = runBlocking {
        val file = File(temp.root, "s.session")
        val keys = SoftwareKey()
        store(file, keys, aad = "com.proteles.auth.client-a").write(sample)
        assertUnreadable(store(file, keys, aad = "com.proteles.auth.client-b"))
    }

    @Test
    fun `a record whose key is gone is unreadable`(): Unit = runBlocking {
        val file = File(temp.root, "s.session")
        store(file, SoftwareKey()).write(sample)
        assertUnreadable(store(file, SoftwareKey()))
        val keyless = object : KeySource {
            override fun existing(): javax.crypto.SecretKey? = null
            override fun getOrCreate(): javax.crypto.SecretKey = error("not for reading")
        }
        assertUnreadable(store(file, keyless))
    }

    @Test
    fun `a record in a format this SDK does not read is unreadable, not a crash`(): Unit = runBlocking {
        val file = File(temp.root, "s.session")
        val keys = SoftwareKey()
        file.writeBytes(AesGcmSessionCipher(keys, "com.proteles.auth.com.example.app".toByteArray()).seal("""{"v":2}""".toByteArray()))
        assertUnreadable(store(file, keys))
    }

    @Test
    fun `the Keystore store is shared across processes, so an in-process lock is refused over it (10_9 item 9)`() {
        val s = store(File(temp.root, "s.session"), SoftwareKey())
        assertTrue(s.sharedAcrossProcesses)
        val configuration = ProtelesConfiguration("https://auth.example.test", "com.example.app", "https://app.example.com/cb")
        try {
            ProtelesClient(configuration, s, CrossProcessLock.inProcessOnly("com.example.app"))
            fail("a shared store with an in-process lock was accepted")
        } catch (e: ProtelesException.Configuration) {
            assertTrue(e.message, e.message!!.contains("cross-process lock"))
        }
        ProtelesClient(configuration, s, FileCrossProcessLock(File(temp.root, "refresh.lock")))
    }

    @Test
    fun `writes replace atomically and leave no temporary files`(): Unit = runBlocking {
        val file = File(temp.root, "s.session")
        val keys = SoftwareKey()
        val s = store(file, keys)
        repeat(5) { s.write(sample) }
        assertEquals(listOf("s.session"), temp.root.list()!!.toList())
        assertNotNull(s.read())
        s.clear()
        assertFalse(file.exists())
        assertNull(s.read())
        s.clear() // clearing nothing is fine
    }

    @Test
    fun `each seal uses a fresh IV`() {
        val cipher = AesGcmSessionCipher(SoftwareKey(), "aad".toByteArray())
        val a = cipher.seal("same".toByteArray())
        val b = cipher.seal("same".toByteArray())
        assertFalse(a.contentEquals(b))
        assertArrayEquals("same".toByteArray(), cipher.open(a))
    }

    @Test
    fun `the file name is a digest, never the client id`() {
        val d = KeystoreTokenStore.digest("com.example.app/../../etc")
        assertTrue(d.matches(Regex("[0-9a-f]{32}")))
    }

    @Test
    fun `a write syncs the directory after the record is in place`(): Unit = runBlocking {
        val file = File(temp.root, "s.session")
        val synced = mutableListOf<Pair<File, ByteArray?>>()
        val s = KeystoreTokenStore(file, AesGcmSessionCipher(SoftwareKey(), "aad".toByteArray())) { dir ->
            synced.add(dir to file.takeIf { it.exists() }?.readBytes())
            true
        }
        s.write(sample)
        assertEquals(1, synced.size)
        assertEquals(temp.root.canonicalFile, synced[0].first.canonicalFile)
        assertArrayEquals("the rename is synced after it happened, not before", file.readBytes(), synced[0].second)
    }

    @Test
    fun `fsyncDirectory syncs a real directory, and reports when it cannot`() {
        assertTrue(fsyncDirectory(temp.root))
        assertFalse(fsyncDirectory(File(temp.root, "missing")))
    }

    @Test
    fun `Android refuses redirects it cannot receive`() {
        fun refused(redirect: String, postLogout: String? = null) {
            try {
                ProtelesAndroid.checkRedirectsForAndroid(
                    ProtelesConfiguration("https://auth.example.test", "c", redirect, postLogoutRedirectUri = postLogout),
                )
                fail("$redirect / $postLogout accepted")
            } catch (e: ProtelesException.Configuration) {
                // expected: refused by the configuration itself (loopback, a private-use scheme) or by the Android check (capitals)
            }
        }
        refused("http://127.0.0.1:8080/cb")
        refused("http://[::1]:8080/cb")
        refused("com.example.app:/cb")
        refused("HTTPS://app.example.com/cb")
        refused("https://App.Example.com/cb")
        refused("https://app.example.com/cb", postLogout = "https://APP.example.com/out")
        refused("https://app.example.com/cb", postLogout = "http://127.0.0.1/out")
        ProtelesAndroid.checkRedirectsForAndroid(
            ProtelesConfiguration("https://auth.example.test", "c", "https://app.example.com/cb", postLogoutRedirectUri = "https://app.example.com/out"),
        )
    }
}
