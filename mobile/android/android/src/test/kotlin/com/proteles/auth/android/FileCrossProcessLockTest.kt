package com.proteles.auth.android

import com.proteles.auth.ProtelesException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.RandomAccessFile
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * The cross-process lock, against a real second process: a JVM started with this
 * test's classpath that takes the same file lock and holds it.
 */
class FileCrossProcessLockTest {
    @get:Rule
    val temp = TemporaryFolder()

    @Test
    fun `waits for another process to release the lock`(): Unit = runBlocking {
        val lockFile = File(temp.root, "refresh.lock")
        val holder = ProcessBuilder(
            File(System.getProperty("java.home"), "bin/java").path,
            "-cp",
            System.getProperty("java.class.path"),
            LockHolderMain::class.java.name,
            lockFile.path,
            "1500",
        ).redirectErrorStream(true).start()
        val out = BufferedReader(InputStreamReader(holder.inputStream))
        try {
            assertEquals("the other process holds the lock", "LOCKED", out.readLine())
            val started = System.nanoTime()
            val waited = FileCrossProcessLock(lockFile).withLock {
                // Only reachable once the other process has let go.
                val line = out.readLine()
                assertEquals("entered before the other process released", "RELEASING", line)
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            }
            assertTrue("waited ${waited}ms for a 1500ms hold", waited >= 1000)
        } finally {
            holder.destroy()
            holder.waitFor(10, TimeUnit.SECONDS)
        }
        assertEquals(0, holder.exitValue())
    }

    /** Starts a second JVM holding [lockFile] for [holdMillis]; returns it once it holds the lock. */
    private fun holder(lockFile: File, holdMillis: Long): Pair<Process, BufferedReader> {
        val process = ProcessBuilder(
            File(System.getProperty("java.home"), "bin/java").path,
            "-cp",
            System.getProperty("java.class.path"),
            LockHolderMain::class.java.name,
            lockFile.path,
            holdMillis.toString(),
        ).redirectErrorStream(true).start()
        val out = BufferedReader(InputStreamReader(process.inputStream))
        assertEquals("the other process holds the lock", "LOCKED", out.readLine())
        return process to out
    }

    @Test
    fun `a waiter gives up after the timeout, without running the action (10_9 item 9)`(): Unit = runBlocking {
        val lockFile = File(temp.root, "refresh.lock")
        val (process, _) = holder(lockFile, 10_000)
        try {
            val started = System.nanoTime()
            var ran = false
            try {
                FileCrossProcessLock(lockFile, timeoutMillis = 300).withLock { ran = true }
                fail("the lock was taken while another process held it")
            } catch (e: ProtelesException.Network) {
                assertTrue(e.message, e.message!!.contains("timed out"))
            }
            val waited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertFalse("the action ran", ran)
            assertTrue("gave up after ${waited}ms", waited in 300..5_000)
        } finally {
            process.destroy()
            process.waitFor(10, TimeUnit.SECONDS)
        }
        // The holder is gone: the lock is free again.
        withTimeout(5_000) { FileCrossProcessLock(lockFile, timeoutMillis = 5_000).withLock { } }
    }

    @Test
    fun `a waiter behind another holder in this process gives up after the timeout too`(): Unit = runBlocking(Dispatchers.Default) {
        val lockFile = File(temp.root, "refresh.lock")
        val inside = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val holding = launch { FileCrossProcessLock(lockFile).withLock { inside.complete(Unit); release.await() } }
        inside.await()
        try {
            FileCrossProcessLock(lockFile, timeoutMillis = 200).withLock { fail("ran while another client held the lock") }
            fail("no timeout")
        } catch (e: ProtelesException.Network) {
            assertTrue(e.message, e.message!!.contains("timed out"))
        }
        release.complete(Unit)
        holding.join()
        withTimeout(5_000) { FileCrossProcessLock(lockFile, timeoutMillis = 200).withLock { } }
    }

    @Test
    fun `a lock file that cannot be opened is a storage failure`(): Unit = runBlocking {
        val notADirectory = temp.newFile("plain-file")
        try {
            FileCrossProcessLock(File(notADirectory, "refresh.lock")).withLock { fail("ran without the lock") }
            fail("no failure")
        } catch (e: ProtelesException.Storage) {
            // expected
        }
    }

    @Test
    fun `two locks on one file in one process queue instead of colliding`(): Unit = runBlocking(Dispatchers.Default) {
        val lockFile = File(temp.root, "refresh.lock")
        val inside = AtomicInteger()
        val maxInside = AtomicInteger()
        (1..40).map { i ->
            async {
                // A fresh instance each time, as two ProtelesClients would have.
                FileCrossProcessLock(lockFile).withLock {
                    val n = inside.incrementAndGet()
                    maxInside.accumulateAndGet(n) { a, b -> maxOf(a, b) }
                    delay(if (i % 3 == 0) 5L else 1L)
                    inside.decrementAndGet()
                }
            }
        }.awaitAll()
        assertEquals("never two holders at once", 1, maxInside.get())
    }

    @Test
    fun `the lock is released when the action throws`(): Unit = runBlocking {
        val lockFile = File(temp.root, "refresh.lock")
        val lock = FileCrossProcessLock(lockFile)
        val thrown = runCatching { lock.withLock { throw IllegalStateException("boom") } }.exceptionOrNull()
        assertTrue(thrown is IllegalStateException)
        withTimeout(5_000) { lock.withLock { } }
        // And the file itself is free for anyone.
        RandomAccessFile(lockFile, "rw").channel.use { ch -> ch.tryLock()!!.release() }
    }
}

/** Run in a second JVM: takes the lock, says so, holds it, says it is letting go, lets go. */
object LockHolderMain {
    @JvmStatic
    fun main(args: Array<String>) {
        val file = File(args[0])
        val holdMillis = args[1].toLong()
        RandomAccessFile(file, "rw").channel.use { channel ->
            val lock = channel.lock()
            println("LOCKED")
            System.out.flush()
            Thread.sleep(holdMillis)
            println("RELEASING")
            System.out.flush()
            lock.release()
        }
    }
}
