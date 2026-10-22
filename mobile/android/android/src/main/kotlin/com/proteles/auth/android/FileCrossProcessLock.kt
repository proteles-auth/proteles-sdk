package com.proteles.auth.android

import android.content.Context
import com.proteles.auth.CrossProcessLock
import com.proteles.auth.ProtelesException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.util.concurrent.ConcurrentHashMap

/**
 * The cross-process refresh lock (docs/mobile-SDKs.md §10.6): an exclusive
 * `FileChannel` lock on a file in the app's private files directory, which
 * every process of the app can reach. The OS releases it if the holder dies,
 * so a crashed process cannot wedge the others.
 *
 * A file lock belongs to the process, not the thread: two holders in one JVM
 * would collide (`OverlappingFileLockException`). So every lock on one file in
 * this process first takes one process-wide [Mutex] for that file — which also
 * makes two `ProtelesClient`s for the same app queue behind each other.
 *
 * **A waiter gives up after [timeoutMillis]** — for the process-wide mutex and
 * the file lock together — with [ProtelesException.Network], without running
 * the action; the holder is not affected. The client then goes on without the
 * lock where it safely can (§10.9 item 9): sign-out clears anyway, and a
 * refresh re-reads the store and returns a usable token if one is there. The
 * wait polls `tryLock` rather than blocking a thread in `lock`, so a cancelled
 * caller stops waiting at once. A lock file that cannot be opened is
 * [ProtelesException.Storage]. Sixty seconds, as on iOS.
 */
public class FileCrossProcessLock @JvmOverloads constructor(
    private val file: File,
    private val timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
) : CrossProcessLock {
    private val gate: Mutex = gates.getOrPut(file.absoluteFile.normalize().path) { Mutex() }

    override suspend fun <T> withLock(action: suspend () -> T): T {
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000
        withTimeoutOrNull(timeoutMillis) { gate.lock() } ?: throw timedOut()
        try {
            val channel = try {
                withContext(Dispatchers.IO) {
                    file.absoluteFile.parentFile?.mkdirs()
                    RandomAccessFile(file, "rw").channel
                }
            } catch (e: IOException) {
                throw ProtelesException.Storage("cannot open the refresh lock at $file", e)
            }
            try {
                val lock = acquire(channel, deadline)
                try {
                    return action()
                } finally {
                    withContext(NonCancellable) { runCatching { lock.release() } }
                }
            } finally {
                withContext(NonCancellable) { runCatching { channel.close() } }
            }
        } finally {
            gate.unlock()
        }
    }

    /** Polls for the file lock until [deadline] (System.nanoTime). */
    private suspend fun acquire(channel: FileChannel, deadline: Long): FileLock {
        while (true) {
            val lock = try {
                withContext(Dispatchers.IO) { channel.tryLock() }
            } catch (e: IOException) {
                throw ProtelesException.Storage("cannot lock $file", e)
            }
            if (lock != null) return lock
            if (System.nanoTime() - deadline >= 0) throw timedOut()
            delay(POLL_MILLIS)
        }
    }

    private fun timedOut() = ProtelesException.Network(
        "timed out after ${timeoutMillis / 1000.0} s waiting for another process's refresh (the cross-process lock at $file)",
    )

    public companion object {
        /** How long a caller waits for another holder by default: sixty seconds, as on iOS. */
        public const val DEFAULT_TIMEOUT_MILLIS: Long = 60_000

        private const val POLL_MILLIS: Long = 20

        private val gates = ConcurrentHashMap<String, Mutex>()

        /** The lock file for [clientId] in the app's private files directory. */
        @JvmStatic
        public fun forClient(context: Context, clientId: String): FileCrossProcessLock =
            FileCrossProcessLock(File(context.applicationContext.filesDir, "com.proteles.auth.${KeystoreTokenStore.digest(clientId)}.lock"))
    }
}
