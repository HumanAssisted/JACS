package ai.hai.jacs.platform

import ai.hai.jacs.*
import android.app.Activity
import android.app.Application
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.util.AtomicFile
import java.io.*
import java.security.MessageDigest
import java.util.concurrent.Executors
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher

interface JacsVaultCallback<T> {
    fun onSuccess(value: T)
    fun onError(error: JacsVaultException)
}

class JacsVaultRequest internal constructor(private val cancelAction: () -> Unit) {
    /** Idempotent. May be called from any thread. */
    fun cancel() = cancelAction()
}

data class JacsVaultIdentity(val agentJson: String, val publicKeyBase64: String)
data class JacsEncryptedTransfer(val code: String, val materialJson: String)

/** Owns the unlocked Rust handle; callers never receive an escapable private-key
 * handle. Construct on the main thread, normally from Activity.onCreate, and call
 * create/unlock/sign/export from the main thread. Results arrive on that thread.
 * Crypto and disk I/O use one worker. Activity stop locks; destruction closes.
 * A cancelled/backgrounded request never delivers an unlocked session or result.
 * No PIN/password/device-credential or server fallback is enabled.
 */
class JacsBiometricVault(
    private val activity: Activity,
    private val alias: String,
) : AutoCloseable {
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor { task -> Thread(task, "jacs-biometric-vault") }
    private val state = JacsVaultState<MobileAgent>()
    private val callbacks = mutableMapOf<JacsVaultState.Ticket, (JacsVaultException) -> Unit>()
    private val prompts = mutableMapOf<JacsVaultState.Ticket, CancellationSignal>()
    private val keystore by lazy { JacsKeystore(alias) } // initialized on worker
    private val recordsDelegate = lazy { EncryptedRecordStore(activity.applicationContext.noBackupFilesDir, alias) }
    private val records by recordsDelegate
    private var foreground = activity.hasWindowFocus()
    private var closed = false

    private val lifecycle = object : Application.ActivityLifecycleCallbacks {
        override fun onActivityResumed(owner: Activity) { if (owner === activity) foreground = true }
        override fun onActivityStopped(owner: Activity) {
            if (owner === activity) { foreground = false; invalidate(JacsVaultException.Code.BACKGROUNDED) }
        }
        override fun onActivityDestroyed(owner: Activity) { if (owner === activity) close() }
        override fun onActivityCreated(owner: Activity, state: Bundle?) {}
        override fun onActivityStarted(owner: Activity) {}
        override fun onActivityPaused(owner: Activity) {}
        override fun onActivitySaveInstanceState(owner: Activity, state: Bundle) {}
    }

    init {
        requireMain()
        require(alias.isNotBlank() && alias.length <= 200) { "Use a nonempty application-owned key alias" }
        activity.application.registerActivityLifecycleCallbacks(lifecycle)
    }

    fun isUnlocked(): Boolean = state.isUnlocked()

    /** Creates ML-DSA-87 only. Existing records are never silently replaced. */
    fun create(title: String, callback: JacsVaultCallback<JacsVaultIdentity>): JacsVaultRequest =
        provision(title, callback) { MobileAgent.create(MobileAlgorithm.PQ2025) }

    /** Receive an encrypted transfer after obtaining its expected identity/key
     * from authenticated registration. Classical material is rejected. */
    fun receive(
        materialJson: String, transferCode: String, expectedAgentId: String,
        expectedPublicKey: ByteArray, title: String, callback: JacsVaultCallback<JacsVaultIdentity>,
    ): JacsVaultRequest {
        val expectedKey = expectedPublicKey.copyOf()
        return provision(title, callback) {
            val material = materialFromJson(materialJson)
            if (material.algorithm != MobileAlgorithm.PQ2025)
                throw JacsVaultException(JacsVaultException.Code.INVALID_RECORD)
            MobileAgent.importPinned(material, transferCode, expectedAgentId, expectedKey, MobileAlgorithm.PQ2025)
        }
    }

    private fun provision(
        title: String, callback: JacsVaultCallback<JacsVaultIdentity>, createAgent: () -> MobileAgent,
    ): JacsVaultRequest = begin(false, true, callback) { ticket ->
        worker.execute {
            try {
                if (records.exists()) throw JacsVaultException(JacsVaultException.Code.ALREADY_EXISTS)
                keystore.ensureWrappingKey()
                val cipher = keystore.prepareProtect()
                main.post { prompt(ticket, title, cipher, callback) {
                    val agent = createAgent()
                    try {
                        if (!state.current(ticket)) throw JacsVaultException(JacsVaultException.Code.CANCELLED)
                        val wrapped = keystore.finishProtect(agent, cipher)
                        if (!state.current(ticket)) throw JacsVaultException(JacsVaultException.Code.CANCELLED)
                        records.writeNew(wrapped)
                        agent
                    } catch (error: Exception) { clear(agent); throw error }
                } }
            } catch (error: Exception) { fail(ticket, callback, error) }
        }
    }

    fun unlock(title: String, callback: JacsVaultCallback<JacsVaultIdentity>): JacsVaultRequest =
        begin(false, true, callback) { ticket -> worker.execute {
            try {
                val wrapped = records.read()
                val cipher = keystore.prepareUnlock(wrapped.wrappedSecret)
                main.post { prompt(ticket, title, cipher, callback) { keystore.finishUnlock(wrapped, cipher) } }
            } catch (error: Exception) { fail(ticket, callback, error) }
        } }

    fun signMessageJson(json: String, callback: JacsVaultCallback<String>): JacsVaultRequest =
        useSession(callback) { it.signMessageJson(json) }

    fun buildRequestAuthHeader(method: String, url: String, body: ByteArray, audience: String,
                               callback: JacsVaultCallback<String>): JacsVaultRequest {
        val bytes = body.copyOf()
        return useSession(callback) { it.buildRequestAuthHeader(method, url, bytes, audience) }
    }

    /** Generate the high-entropy six-word code locally, export ciphertext, and
     * relock before delivering the result. Never send code and ciphertext to
     * the same relay; show the code directly to the receiving user. */
    fun createTransfer(callback: JacsVaultCallback<JacsEncryptedTransfer>): JacsVaultRequest =
        useSession(callback, lockAfter = true) {
            val code = generateTransferCode()
            JacsEncryptedTransfer(code, materialToJson(it.exportEncryptedAgent(code)))
        }

    private fun <T> useSession(callback: JacsVaultCallback<T>, lockAfter: Boolean = false,
                               operation: (MobileAgent) -> T): JacsVaultRequest =
        begin(true, false, callback) { ticket ->
            val agent = state.session(ticket)
            worker.execute {
                try {
                    if (!state.current(ticket)) return@execute
                    val result = operation(agent)
                    main.post { complete(ticket, callback, result, lockAfter) }
                } catch (error: Exception) { fail(ticket, callback, error) }
            }
        }

    /** Lock/logout clears the in-memory handle and cancels pending work. The
     * encrypted record remains available for the next biometric unlock. */
    fun lock() { requireMain(); invalidate(JacsVaultException.Code.CANCELLED) }

    /** Explicit local erase. Clear the record before deleting its wrapping key;
     * a storage failure retains the key so retry/recovery remains possible. */
    fun delete(callback: JacsVaultCallback<Unit>): JacsVaultRequest {
        lock()
        return begin(false, false, callback) { ticket -> worker.execute {
            try {
                if (!state.current(ticket)) return@execute
                records.delete()
                keystore.deleteWrappingKey()
                main.post { complete(ticket, callback, Unit) }
            } catch (error: Exception) { fail(ticket, callback, error) }
        } }
    }

    override fun close() {
        requireMain()
        if (closed) return
        closed = true
        activity.application.unregisterActivityLifecycleCallbacks(lifecycle)
        try { invalidate(JacsVaultException.Code.CLOSED, true) }
        finally {
            // Already queued work runs cleanup, including stale unlocked candidates.
            worker.execute { if (recordsDelegate.isInitialized()) records.close() }
            worker.shutdown()
        }
    }

    private fun <T> begin(needsSession: Boolean, opensSession: Boolean, callback: JacsVaultCallback<T>,
                          start: (JacsVaultState.Ticket) -> Unit): JacsVaultRequest {
        requireMain()
        if (!foreground && !closed) {
            callback.onError(JacsVaultException(JacsVaultException.Code.BACKGROUNDED))
            return JacsVaultRequest {}
        }
        val ticket = try { state.begin(needsSession, opensSession) } catch (error: JacsVaultException) {
            callback.onError(error); return JacsVaultRequest {}
        }
        callbacks[ticket] = { callback.onError(it) }
        val availability = if (opensSession) biometricAvailabilityError() else null
        if (availability != null) fail(ticket, callback, JacsVaultException(availability))
        else start(ticket)
        return JacsVaultRequest {
            if (state.cancel(ticket)) main.post {
                if (state.owns(ticket)) invalidate(JacsVaultException.Code.CANCELLED)
            }
        }
    }

    private fun prompt(ticket: JacsVaultState.Ticket, title: String, cipher: Cipher,
                       callback: JacsVaultCallback<JacsVaultIdentity>, open: () -> MobileAgent) {
        if (!state.current(ticket)) return
        if (!foreground || activity.isFinishing || activity.isDestroyed) {
            invalidate(JacsVaultException.Code.BACKGROUNDED); return
        }
        val availability = biometricAvailabilityError()
        if (availability != null) {
            fail(ticket, callback, JacsVaultException(availability)); return
        }
        if (!state.bindCipher(ticket, cipher)) return
        val cancellation = CancellationSignal()
        prompts[ticket] = cancellation
        try {
            BiometricPrompt.Builder(activity)
                .setTitle(title)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButton("Cancel", activity.mainExecutor) { _, _ ->
                    if (state.owns(ticket)) invalidate(JacsVaultException.Code.CANCELLED)
                }
                .build().authenticate(BiometricPrompt.CryptoObject(cipher), cancellation, activity.mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationFailed() { /* Nonterminal: platform allows retry. */ }
                        override fun onAuthenticationError(code: Int, message: CharSequence) {
                            fail(ticket, callback, JacsVaultException(promptError(code)))
                        }
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (!state.current(ticket)) return
                            if (!state.authenticate(ticket, result.cryptoObject?.cipher)) {
                                fail(ticket, callback, JacsVaultException(JacsVaultException.Code.INTEGRITY)); return
                            }
                            prompts.remove(ticket)
                            worker.execute {
                                var candidate: MobileAgent? = null
                                try {
                                    if (!state.current(ticket)) return@execute
                                    candidate = open()
                                    val agent = candidate
                                    val identity = JacsVaultIdentity(agent.exportAgentJson(), agent.getPublicKeyBase64())
                                    // Transfer ownership to the main-thread state only if current.
                                    main.post {
                                        if (state.install(ticket, agent)) complete(ticket, callback, identity)
                                        else dispose(agent)
                                    }
                                    candidate = null
                                } catch (error: Exception) { fail(ticket, callback, error) }
                                finally { candidate?.let { clear(it) } }
                            }
                        }
                    })
        } catch (error: Exception) { fail(ticket, callback, error) }
    }

    private fun <T> complete(ticket: JacsVaultState.Ticket, callback: JacsVaultCallback<T>, result: T,
                              lockAfter: Boolean = false) {
        if (!state.finish(ticket)) return
        callbacks.remove(ticket)
        prompts.remove(ticket)
        if (lockAfter) invalidate(JacsVaultException.Code.CANCELLED)
        callback.onSuccess(result)
    }
    private fun <T> fail(ticket: JacsVaultState.Ticket, callback: JacsVaultCallback<T>, error: Exception) {
        main.post {
            if (!state.finish(ticket)) return@post
            callbacks.remove(ticket)
            prompts.remove(ticket)?.cancel()
            callback.onError(mapError(error))
        }
    }
    private fun invalidate(code: JacsVaultException.Code, permanently: Boolean = false) {
        val invalidated = state.invalidate(permanently)
        // Schedule clearing before calling application code, which may throw.
        invalidated.session?.let { dispose(it) }
        invalidated.ticket?.let { ticket ->
            prompts.remove(ticket)?.cancel()
            callbacks.remove(ticket)?.invoke(JacsVaultException(code))
        }
    }
    private fun dispose(agent: MobileAgent) {
        // close() can race a previously posted completion. Its worker has then
        // drained or is draining, so release the stale handle on this thread.
        if (worker.isShutdown) clear(agent) else worker.execute { clear(agent) }
    }
    private fun requireMain() { check(Looper.myLooper() === Looper.getMainLooper()) { "Call vault APIs on the main thread" } }
    private fun biometricAvailabilityError(): JacsVaultException.Code? {
        val manager = activity.getSystemService(BiometricManager::class.java)
        return when (manager?.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> null
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> JacsVaultException.Code.NOT_ENROLLED
            else -> JacsVaultException.Code.UNAVAILABLE
        }
    }
    private fun clear(agent: MobileAgent) {
        try { agent.clearSecrets() } catch (_: Exception) { /* Drop still releases the owned Rust handle. */ }
        finally { agent.close() }
    }

    companion object {
        internal fun promptError(code: Int): JacsVaultException.Code = when (code) {
            BiometricPrompt.BIOMETRIC_ERROR_CANCELED, BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
            BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT -> JacsVaultException.Code.CANCELLED
            BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT -> JacsVaultException.Code.LOCKOUT
            BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT -> JacsVaultException.Code.PERMANENT_LOCKOUT
            BiometricPrompt.BIOMETRIC_ERROR_NO_BIOMETRICS -> JacsVaultException.Code.NOT_ENROLLED
            else -> JacsVaultException.Code.UNAVAILABLE
        }
        internal fun mapError(error: Exception): JacsVaultException = when (error) {
            is JacsVaultException -> error
            is KeyPermanentlyInvalidatedException -> JacsVaultException(JacsVaultException.Code.KEY_INVALIDATED)
            is UserNotAuthenticatedException -> JacsVaultException(JacsVaultException.Code.LOCKED)
            is AEADBadTagException -> JacsVaultException(JacsVaultException.Code.INTEGRITY)
            is IOException -> JacsVaultException(JacsVaultException.Code.STORAGE)
            is IllegalArgumentException -> JacsVaultException(JacsVaultException.Code.INVALID_RECORD)
            else -> JacsVaultException(JacsVaultException.Code.CRYPTO)
        }
    }
}

/** App-private, backup-excluded, atomic ciphertext record. A restored record on
 * another device cannot recover its non-exportable Keystore wrapping key. */
internal class EncryptedRecordStore(directory: File, alias: String) : AutoCloseable {
    private val name = MessageDigest.getInstance("SHA-256").digest(alias.toByteArray())
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private val file = AtomicFile(File(directory, "jacs-vault-$name.bin"))
    // Keep one owner across threads/processes, including the biometric prompt.
    // AtomicFile alone does not serialize exists()->write or Keystore creation.
    // The lock file is never unlinked, avoiding an inode-replacement lock race.
    private val ownerChannel = RandomAccessFile(File(directory, "jacs-vault-$name.lock"), "rw").channel
    private val ownerLock = try {
        ownerChannel.tryLock() ?: throw JacsVaultException(JacsVaultException.Code.BUSY)
    } catch (error: Exception) {
        ownerChannel.close()
        throw JacsVaultException(JacsVaultException.Code.BUSY)
    }
    private fun requireOwner() {
        if (!ownerLock.isValid) throw JacsVaultException(JacsVaultException.Code.CLOSED)
    }
    fun exists(): Boolean {
        requireOwner()
        return file.baseFile.exists() || File(file.baseFile.path + ".bak").exists()
    }
    fun writeNew(wrapped: JacsKeystore.WrappedMaterial) {
        if (exists()) throw JacsVaultException(JacsVaultException.Code.ALREADY_EXISTS)
        val material = wrapped.materialJson.toByteArray(Charsets.UTF_8)
        require(material.size in 1..MAX_MATERIAL && wrapped.wrappedSecret.size in 29..4096)
        val stream = file.startWrite()
        try {
            val output = DataOutputStream(stream)
            output.writeInt(MAGIC)
            output.writeInt(material.size); output.write(material)
            output.writeInt(wrapped.wrappedSecret.size); output.write(wrapped.wrappedSecret)
            output.flush()
            file.finishWrite(stream)
        } catch (error: Exception) { file.failWrite(stream); throw error }
    }
    fun read(): JacsKeystore.WrappedMaterial {
        if (!exists()) throw JacsVaultException(JacsVaultException.Code.MISSING_RECORD)
        try {
            DataInputStream(file.openRead()).use { input ->
                require(input.readInt() == MAGIC)
                val size = input.readInt(); require(size in 1..MAX_MATERIAL)
                val material = ByteArray(size).also { input.readFully(it) }
                val secretSize = input.readInt(); require(secretSize in 29..4096)
                val secret = ByteArray(secretSize).also { input.readFully(it) }
                require(input.read() == -1)
                val json = String(material, Charsets.UTF_8)
                require(materialFromJson(json).algorithm == MobileAlgorithm.PQ2025)
                return JacsKeystore.WrappedMaterial(json, secret)
            }
        } catch (error: EOFException) { throw JacsVaultException(JacsVaultException.Code.INVALID_RECORD) }
    }
    fun delete() {
        requireOwner()
        file.delete()
        if (listOf("", ".bak", ".new").any { File(file.baseFile.path + it).exists() })
            throw IOException("Unable to delete encrypted vault record")
    }
    override fun close() {
        try { if (ownerLock.isValid) ownerLock.release() }
        finally { ownerChannel.close() }
    }
    companion object { private const val MAGIC = 0x4a564c31; private const val MAX_MATERIAL = 4 * 1024 * 1024 }
}
