package com.proteles.auth.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import com.proteles.auth.StoredSession
import com.proteles.auth.TokenStore
import com.proteles.auth.UnreadableSessionException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The session at rest (docs/mobile-SDKs.md §10.5): the token record encrypted
 * with AES-256-GCM under a key generated inside the Android Keystore — the key
 * never exists in the app's memory — and kept in the app's private
 * `noBackupFilesDir`. Never `SharedPreferences`, never a plaintext file.
 *
 * `noBackupFilesDir`, because a Keystore key is not backed up: a ciphertext
 * restored to a new device could never be opened, so it is better not to carry
 * it there. A record that can never be opened (the key was invalidated, the
 * file was tampered with, it is another format) is [UnreadableSessionException]:
 * the client reads that as "nobody signed in", sign-out deletes it and reports
 * that its refresh token could not be revoked (§10.9 item 6), and the next
 * sign-in overwrites it. Any other failure to read is reported as storage, never
 * as signed out.
 *
 * Every process of the app reaches the same file, so the store is
 * [shared across processes][sharedAcrossProcesses]: a client over it must use
 * [FileCrossProcessLock] (§10.9 item 9).
 *
 * Writes are atomic (a temporary file, fsync'd, renamed over the old one), so a
 * reader in another process sees the old session or the new one, never half of
 * one — and durable: the directory is fsync'd after the rename, so a power loss
 * straight after a refresh cannot bring back the record holding the refresh
 * token the server has just rotated away (§4 "persist before you use").
 */
public class KeystoreTokenStore internal constructor(
    private val file: File,
    private val cipher: SessionCipher,
    /** Makes the rename durable; a seam so a test can see that it is called, and when. */
    private val syncDirectory: (File) -> Boolean = ::fsyncDirectory,
) : TokenStore {

    override val sharedAcrossProcesses: Boolean get() = true

    override suspend fun read(): StoredSession? = withContext(Dispatchers.IO) {
        val sealed = try {
            file.readBytes()
        } catch (e: FileNotFoundException) {
            return@withContext null
        }
        // A record that can never be opened is not deleted here: a read holds no
        // lock, and another process may have just renamed a fresh record into
        // place. Sign-out deletes it, and the next sign-in overwrites it.
        val plain = cipher.open(sealed) ?: throw UnreadableSessionException("the stored session cannot be opened with this app's Keystore key")
        try {
            StoredSession.decode(plain)
        } catch (e: IllegalArgumentException) {
            throw UnreadableSessionException("the stored session is not in a format this SDK reads", e)
        }
    }

    override suspend fun write(session: StoredSession): Unit = withContext(Dispatchers.IO) {
        val sealed = cipher.seal(session.encode())
        val dir = file.parentFile ?: throw IOException("no directory for $file")
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("cannot create $dir")
        val tmp = File.createTempFile(file.name, ".tmp", dir)
        try {
            FileOutputStream(tmp).use { out ->
                out.write(sealed)
                out.fd.sync()
            }
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE)
            syncDirectory(dir)
        } finally {
            tmp.delete()
        }
    }

    override suspend fun clear(): Unit = withContext(Dispatchers.IO) {
        if (!file.delete() && file.exists()) throw IOException("cannot delete $file")
    }

    public companion object {
        /**
         * The store for [clientId]: the Keystore alias `com.proteles.auth.<clientId>`
         * (the same name iOS gives its Keychain service), and a file in
         * `noBackupFilesDir` named from a digest of the client id.
         */
        @JvmStatic
        public fun create(context: Context, clientId: String): KeystoreTokenStore {
            val alias = "com.proteles.auth.$clientId"
            val dir = context.applicationContext.noBackupFilesDir
            return KeystoreTokenStore(
                File(dir, "com.proteles.auth.${digest(clientId)}.session"),
                AesGcmSessionCipher(AndroidKeystoreKey(alias), aad = alias.toByteArray(Charsets.UTF_8)),
            )
        }

        /** 32 hex characters of SHA-256: a file-name-safe name for any client id. */
        internal fun digest(value: String): String {
            val hex = "0123456789abcdef"
            val bytes = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
            return buildString { for (b in bytes.copyOf(16)) append(hex[(b.toInt() shr 4) and 0xF]).append(hex[b.toInt() and 0xF]) }
        }
    }
}

/**
 * fsync on [dir], which is what makes a rename in it survive a power loss on
 * Linux filesystems (ext4, f2fs). Returns whether it happened: a filesystem or
 * platform that cannot open a directory for syncing is not an error — the
 * rename is still atomic, just not yet durable.
 */
internal fun fsyncDirectory(dir: File): Boolean = try {
    FileChannel.open(dir.toPath(), StandardOpenOption.READ).use { it.force(true) }
    true
} catch (e: IOException) {
    false
} catch (e: UnsupportedOperationException) {
    false
}

/** Seals and opens the session record. [open] returns null for a record that can never be opened. */
internal interface SessionCipher {
    fun seal(plain: ByteArray): ByteArray

    fun open(sealed: ByteArray): ByteArray?
}

/** Where the AES key lives. */
internal interface KeySource {
    /** The key, or null when there is none (nothing was ever sealed, or it was deleted). */
    fun existing(): SecretKey?

    fun getOrCreate(): SecretKey
}

/**
 * AES-256-GCM, 96-bit IV chosen by the cipher, 128-bit tag, with [aad] (the key
 * alias) bound in so a record cannot be moved between clients. Format:
 * `0x01 | ivLength | iv | ciphertext+tag`.
 */
internal class AesGcmSessionCipher(private val keys: KeySource, private val aad: ByteArray) : SessionCipher {
    override fun seal(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, keys.getOrCreate())
        cipher.updateAAD(aad)
        val body = cipher.doFinal(plain)
        val iv = cipher.iv
        return byteArrayOf(FORMAT, iv.size.toByte()) + iv + body
    }

    override fun open(sealed: ByteArray): ByteArray? {
        if (sealed.size < 2 || sealed[0] != FORMAT) return null
        val ivLength = sealed[1].toInt() and 0xFF
        if (ivLength < 12 || sealed.size < 2 + ivLength + TAG_BITS / 8) return null
        val key = keys.existing() ?: return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, sealed, 2, ivLength))
            cipher.updateAAD(aad)
            cipher.doFinal(sealed, 2 + ivLength, sealed.size - 2 - ivLength)
        } catch (e: AEADBadTagException) {
            null
        } catch (e: KeyPermanentlyInvalidatedException) {
            null
        } catch (e: UnrecoverableKeyException) {
            null
        } catch (e: InvalidKeyException) {
            null
        }
    }

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val TAG_BITS = 128
        const val FORMAT: Byte = 1
    }
}

/**
 * An AES-256 key generated inside the Android Keystore: encrypt/decrypt only,
 * GCM, no user-authentication requirement (a background refresh must be able to
 * open the record while the device is locked but has been unlocked since boot).
 */
internal class AndroidKeystoreKey(private val alias: String) : KeySource {
    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    override fun existing(): SecretKey? = try {
        keyStore().getKey(alias, null) as? SecretKey
    } catch (e: UnrecoverableKeyException) {
        null
    }

    /** Called only under the cross-process lock (every write is), so two processes cannot both create it. */
    override fun getOrCreate(): SecretKey = existing() ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).run {
        init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        generateKey()
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
    }
}
