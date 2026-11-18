package ai.hai.jacs.platform

import ai.hai.jacs.*
import android.os.Build
import android.hardware.biometrics.BiometricPrompt
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

// KeyInfo documents -1 for per-use authentication. Android 15's Keystore2
// SecretKeyFactory also reports 0 when KM_TAG_AUTH_TIMEOUT is absent.
// Neither representation permits a positive authentication time window.
internal fun isPerUseAuthenticationDuration(seconds: Int): Boolean = seconds == -1 || seconds == 0

/** Default custody path for transferable ML-DSA-87 (pq2025) identities.
 * Biometrics gate a generated, non-exportable HMAC root; ML-DSA stays in Rust.
 * Android API 30+. Each derivation requires a fresh BiometricPrompt CryptoObject.
 * Version 1 AES records remain readable. Persist only WrappedMaterial: encrypted
 * transferable identity plus a public, versioned local-password descriptor.
 */
class JacsKeystore(private val alias: String) {
    data class WrappedMaterial(val materialJson: String, val wrappedSecret: ByteArray,
        val pendingMaterialJson: String? = null)
    private val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val derivationAlias = rootAlias(alias)

    /** A fresh operation, never an authentication window or reusable MAC result. */
    internal sealed class Authentication {
        abstract val operation: Any
        abstract fun cryptoObject(): BiometricPrompt.CryptoObject
        abstract fun matches(result: BiometricPrompt.CryptoObject?): Boolean
        class Decrypt(val cipher: Cipher) : Authentication() {
            override val operation: Any get() = cipher
            override fun cryptoObject() = BiometricPrompt.CryptoObject(cipher)
            override fun matches(result: BiometricPrompt.CryptoObject?) = result?.cipher === cipher
        }
        class Derive(val mac: Mac, descriptor: ByteArray) : Authentication() {
            private val frozenDescriptor = descriptor.copyOf()
            override val operation: Any get() = mac
            override fun cryptoObject() = BiometricPrompt.CryptoObject(mac)
            override fun matches(result: BiometricPrompt.CryptoObject?) = result?.mac === mac
            fun descriptor() = frozenDescriptor.copyOf()
            fun requireDescriptor(actual: ByteArray) {
                if (!frozenDescriptor.contentEquals(actual))
                    throw JacsVaultException(JacsVaultException.Code.INTEGRITY)
            }
        }
    }

    /** New roots are generated inside Keystore; raw root key bytes never enter the app.
     * Call only while no record exists, holding the record owner's lock, which serializes
     * creation and all subsequent persistence. An orphan root left by an interrupted
     * ceremony is validated and reused; a weaker or imported one is rejected, not replaced.
     * One that Keystore reports permanently invalidated protects no record and can never
     * authorize again, so it is replaced once, and only while it is this vault's HMAC key.
     */
    internal fun prepareProvision(): Authentication.Derive {
        require(Build.VERSION.SDK_INT >= 30)
        val descriptor = byteArrayOf(2) + ByteArray(32).also { SecureRandom().nextBytes(it) }
        if (store.containsAlias(derivationAlias)) {
            try { return prepareDerivation(descriptor) }
            catch (error: android.security.keystore.KeyPermanentlyInvalidatedException) {
                if (!deleteOwnKey(derivationAlias)) throw error
            }
        }
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(derivationAlias, KeyProperties.PURPOSE_SIGN)
                .setKeySize(256).setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true).build())
            generateKey()
        }
        return prepareDerivation(descriptor)
    }

    internal fun validatedDerivationKey(): SecretKey {
        try {
            val key = store.getKey(derivationAlias, null) as? SecretKey
                ?: throw JacsVaultException(JacsVaultException.Code.KEY_INVALIDATED)
            val info = SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
                .getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (key.algorithm != KeyProperties.KEY_ALGORITHM_HMAC_SHA256 || info.keySize != 256 ||
                info.origin != KeyProperties.ORIGIN_GENERATED || info.purposes != KeyProperties.PURPOSE_SIGN ||
                info.digests.toSet() != setOf(KeyProperties.DIGEST_SHA256) ||
                !info.isUserAuthenticationRequired || info.userAuthenticationType != KeyProperties.AUTH_BIOMETRIC_STRONG ||
                !isPerUseAuthenticationDuration(info.userAuthenticationValidityDurationSeconds) ||
                !info.isInvalidatedByBiometricEnrollment || info.isUserAuthenticationValidWhileOnBody)
                throw JacsVaultException(JacsVaultException.Code.KEY_POLICY)
            return key
        } catch (error: JacsVaultException) { throw error }
        catch (error: android.security.keystore.KeyPermanentlyInvalidatedException) {
            throw JacsVaultException(JacsVaultException.Code.KEY_INVALIDATED, error)
        } catch (error: Exception) { throw JacsVaultException(JacsVaultException.Code.KEY_POLICY, error) }
    }

    private fun prepareDerivation(descriptor: ByteArray): Authentication.Derive {
        derivationInput(alias, descriptor) // Reject malformed versions before accessing a key.
        return Authentication.Derive(Mac.getInstance("HmacSHA256").apply { init(validatedDerivationKey()) }, descriptor)
    }

    internal fun prepareOpen(descriptor: ByteArray): Authentication = when (descriptor.firstOrNull()) {
        1.toByte() -> Authentication.Decrypt(prepareUnlock(descriptor))
        2.toByte() -> prepareDerivation(descriptor)
        else -> throw JacsVaultException(JacsVaultException.Code.INVALID_RECORD)
    }

    /** The same ephemeral envelope password may serve only this authenticated ceremony.
     * JVM/FFI strings cannot be reliably wiped; mutable outputs are always cleared.
     */
    internal fun <T> withProvisionPassword(auth: Authentication.Derive, operation: (String) -> T): T {
        val bytes = auth.mac.doFinal(derivationInput(alias, auth.descriptor()))
        var encoded: ByteArray? = null
        try {
            if (bytes.size != 32) throw JacsVaultException(JacsVaultException.Code.INTEGRITY)
            encoded = Base64.getEncoder().encode(bytes)
            return operation(String(encoded, Charsets.UTF_8))
        } finally { bytes.fill(0); encoded?.fill(0) }
    }

    internal fun <T> withOpenedPassword(wrapped: WrappedMaterial, auth: Authentication, operation: (String) -> T): T =
        when (auth) {
            is Authentication.Decrypt -> withUnlockedPassword(wrapped, auth.cipher, operation)
            is Authentication.Derive -> { auth.requireDescriptor(wrapped.wrappedSecret); withProvisionPassword(auth, operation) }
        }

    internal fun open(wrapped: WrappedMaterial, auth: Authentication): MobileAgent =
        withOpenedPassword(wrapped, auth) { MobileAgent.importEncryptedAgent(materialFromJson(wrapped.materialJson), it) }

    companion object {
        internal fun validateDescriptor(descriptor: ByteArray) {
            val valid = when (descriptor.firstOrNull()) {
                1.toByte() -> descriptor.size in 29..4096
                2.toByte() -> descriptor.size == 33
                else -> false
            }
            if (!valid) throw JacsVaultException(JacsVaultException.Code.INVALID_RECORD)
        }

        /** Stable across key rotation: never include changing identity or ciphertext here. */
        internal fun derivationInput(alias: String, descriptor: ByteArray): ByteArray {
            if (descriptor.size != 33 || descriptor[0] != 2.toByte() || alias.isBlank() || alias.length > 200)
                throw JacsVaultException(JacsVaultException.Code.INVALID_RECORD)
            val domain = "JACS-ANDROID-VAULT-PASSWORD-V2\u0000".toByteArray(Charsets.US_ASCII)
            val owner = alias.toByteArray(Charsets.UTF_8)
            return ByteBuffer.allocate(domain.size + 4 + owner.size + descriptor.size)
                .put(domain).putInt(owner.size).put(owner).put(descriptor).array()
        }

        /** A vault creates AES keys only at its alias and HMAC roots only at rootAlias(alias).
         * One application alias can be another plus ".hmac-v2", so a name alone may be another
         * vault's key, but an entry alias with its key algorithm has exactly one owner. */
        internal fun rootAlias(alias: String) = "$alias.hmac-v2"
        internal fun ownsKey(alias: String, entry: String, algorithm: String?): Boolean = when (algorithm) {
            KeyProperties.KEY_ALGORITHM_AES -> entry == alias
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256 -> entry == rootAlias(alias)
            else -> false
        }
    }

    /** Loading an existing alias never silently weakens the required policy. */
    fun ensureWrappingKey() {
        if (!store.containsAlias(alias)) createWrappingKey()
        validatedWrappingKey()
    }

    internal fun validatedWrappingKey(): SecretKey {
        try {
            val key = store.getKey(alias, null) as? SecretKey
                ?: throw JacsVaultException(JacsVaultException.Code.KEY_INVALIDATED)
            val info = SecretKeyFactory.getInstance("AES", "AndroidKeyStore")
                .getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (key.algorithm != KeyProperties.KEY_ALGORITHM_AES || info.keySize != 256 ||
                info.purposes != (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT) ||
                info.blockModes.toSet() != setOf(KeyProperties.BLOCK_MODE_GCM) ||
                info.encryptionPaddings.toSet() != setOf(KeyProperties.ENCRYPTION_PADDING_NONE) ||
                !info.isUserAuthenticationRequired ||
                info.userAuthenticationType != KeyProperties.AUTH_BIOMETRIC_STRONG ||
                !isPerUseAuthenticationDuration(info.userAuthenticationValidityDurationSeconds) ||
                !info.isInvalidatedByBiometricEnrollment || info.isUserAuthenticationValidWhileOnBody) {
                throw JacsVaultException(JacsVaultException.Code.KEY_POLICY)
            }
            return key
        } catch (error: JacsVaultException) {
            throw error
        } catch (error: android.security.keystore.KeyPermanentlyInvalidatedException) {
            throw JacsVaultException(JacsVaultException.Code.KEY_INVALIDATED, error)
        } catch (error: Exception) {
            throw JacsVaultException(JacsVaultException.Code.KEY_POLICY, error)
        }
    }

    fun createWrappingKey() {
        require(Build.VERSION.SDK_INT >= 30) { "JacsKeystore requires API 30+" }
        check(!store.containsAlias(alias)) { "Refusing to replace an existing wrapping key" }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .build())
        generator.generateKey()
    }

    /** Pass the returned Cipher to BiometricPrompt.CryptoObject(cipher).
     * Call finishProtect only with the Cipher in onAuthenticationSucceeded.
     */
    fun prepareProtect(): Cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, validatedWrappingKey())
    }

    fun finishProtect(agent: MobileAgent, authenticatedCipher: Cipher): WrappedMaterial {
        val entropy = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val passwordBytes = Base64.getEncoder().encode(entropy)
        entropy.fill(0)
        try {
            val material = agent.exportEncryptedAgent(String(passwordBytes, Charsets.UTF_8))
            // Keystore may flush AAD immediately. Submit it only AFTER the
            // CryptoObject has been authenticated, or the Cipher is poisoned.
            authenticatedCipher.updateAAD(alias.toByteArray(Charsets.UTF_8))
            val ciphertext = authenticatedCipher.doFinal(passwordBytes)
            val iv = authenticatedCipher.iv
            check(iv.size == 12) { "Unexpected AES-GCM IV size" }
            // Version 1 | 12-byte nonce | ciphertext with 16-byte tag.
            return WrappedMaterial(materialToJson(material), byteArrayOf(1) + iv + ciphertext)
        } finally { passwordBytes.fill(0) }
    }

    fun prepareUnlock(wrappedSecret: ByteArray): Cipher {
        require(wrappedSecret.size in 29..4096 && wrappedSecret[0] == 1.toByte()) {
            "Malformed wrapped envelope secret"
        }
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, validatedWrappingKey(),
                GCMParameterSpec(128, wrappedSecret.copyOfRange(1, 13)))
        }
    }

    /** Call after authenticating prepareUnlock's Cipher using BiometricPrompt.
     * The app must clearSecrets() on background/logout and after transfer.
     */
    fun finishUnlock(wrapped: WrappedMaterial, authenticatedCipher: Cipher): MobileAgent =
        withUnlockedPassword(wrapped, authenticatedCipher) { password ->
            MobileAgent.importEncryptedAgent(materialFromJson(wrapped.materialJson), password)
        }

    /** Native vault scope only; never return the local wrapping password. */
    internal fun <T> withUnlockedPassword(wrapped: WrappedMaterial, authenticatedCipher: Cipher,
        operation: (String) -> T): T {
        require(wrapped.wrappedSecret.size in 29..4096 && wrapped.wrappedSecret[0] == 1.toByte())
        authenticatedCipher.updateAAD(alias.toByteArray(Charsets.UTF_8))
        val password = authenticatedCipher.doFinal(wrapped.wrappedSecret.copyOfRange(13, wrapped.wrappedSecret.size))
        try {
            return operation(String(password, Charsets.UTF_8))
        } finally { password.fill(0) }
    }

    /** Legacy low-level AES API: never delete a different vault's HMAC root. */
    fun deleteWrappingKey() {
        if (!deleteOwnKey(alias)) throw JacsVaultException(JacsVaultException.Code.KEY_POLICY)
    }

    /** A readable record's scheme owns exactly one alias; any other key there fails closed.
     * Without a readable record the caller has already erased the ciphertext, so this
     * vault's own keys protect nothing: remove them and silently keep any other entry. */
    internal fun deleteRecordKey(descriptor: ByteArray?) {
        if (descriptor == null) { deleteOwnKey(alias); deleteOwnKey(derivationAlias); return }
        validateDescriptor(descriptor)
        if (!deleteOwnKey(if (descriptor[0] == 1.toByte()) alias else derivationAlias))
            throw JacsVaultException(JacsVaultException.Code.KEY_POLICY)
    }

    /** Deletes [entry] only while it holds this vault's key (see ownsKey). Returns false,
     * deleting nothing, when a key this vault cannot own occupies the alias. */
    private fun deleteOwnKey(entry: String): Boolean {
        val key = store.getKey(entry, null) ?: return true
        if (!ownsKey(alias, entry, key.algorithm)) return false
        store.deleteEntry(entry)
        return true
    }
}

/** Explicit classical-compatibility option, not the default identity mode.
 * Non-exportable AndroidKeyStore ES256 signer. BiometricPrompt must authorize
 * the key before entering Rust. A short (15s) authorization window allows the
 * synchronous UniFFI callback to sign without blocking the Android UI thread.
 * Availability and actual hardware backing depend on the device; StrongBox is
 * explicitly required if requireStrongBox=true and never silently downgraded.
 */
class JacsKeystoreSigner private constructor(
    private var privateKey: PrivateKey?,
    private val publicBytes: ByteArray,
) : PlatformSigner {
    private var active = true

    override fun algorithm() = MobileAlgorithm.ES256
    override fun publicKey(): ByteArray = publicBytes.copyOf()

    @Synchronized
    override fun sign(message: ByteArray): ByteArray {
        if (!active) throw PlatformSignerException.AuthenticationRequired()
        val key = privateKey ?: throw PlatformSignerException.AuthenticationRequired()
        try {
            val signer = Signature.getInstance("SHA256withECDSA")
            // Use the validated key reference, not a fresh lookup of a replaceable alias.
            signer.initSign(key)
            signer.update(message) // hash once, inside SHA256withECDSA
            return derToP1363(signer.sign())
        } catch (error: UserNotAuthenticatedException) {
            throw PlatformSignerException.AuthenticationRequired()
        } catch (error: Exception) {
            throw PlatformSignerException.Failed("Android Keystore signing failed")
        }
    }

    @Synchronized
    override fun clearSecrets() { active = false; privateKey = null }

    companion object {
        fun create(alias: String, requireStrongBox: Boolean = false): JacsKeystoreSigner {
            require(Build.VERSION.SDK_INT >= 30) { "JacsKeystoreSigner requires API 30+" }
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            check(!store.containsAlias(alias)) { "Refusing to overwrite signing key" }
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(15, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
            if (requireStrongBox) builder.setIsStrongBoxBacked(true)
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                initialize(builder.build())
                generateKeyPair()
            }
            return load(alias)
        }

        /** Reject aliases created under a weaker authentication policy. This
         * validates the policy, not StrongBox backing: only create(..., true)
         * promises StrongBox. Unknown/unreadable policy always fails closed.
         */
        fun load(alias: String): JacsKeystoreSigner {
            if (Build.VERSION.SDK_INT < 30) {
                throw PlatformSignerException.Unavailable("Keystore policy validation requires API 30+")
            }
            try {
                val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                val key = store.getKey(alias, null) as? PrivateKey
                    ?: throw IllegalArgumentException("Missing private key")
                val info = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                    .getKeySpec(key, KeyInfo::class.java)
                check(key.algorithm == KeyProperties.KEY_ALGORITHM_EC && info.keySize == 256)
                check(info.isUserAuthenticationRequired)
                check(info.userAuthenticationType == KeyProperties.AUTH_BIOMETRIC_STRONG)
                check(info.userAuthenticationValidityDurationSeconds == 15)
                check(!info.isUserAuthenticationValidWhileOnBody)
                check(info.purposes == (KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY))
                check(info.digests.toSet() == setOf(KeyProperties.DIGEST_SHA256))
                // Enrollment invalidation only applies to per-use authentication
                // keys; it cannot be asserted for this 15-second-window signer.
                val publicKey = store.getCertificate(alias)?.publicKey as? ECPublicKey
                    ?: throw IllegalArgumentException("Missing EC public key")
                return JacsKeystoreSigner(key, encodePublic(publicKey))
            } catch (error: Exception) {
                throw PlatformSignerException.Unavailable("Keystore signing key or required biometric policy unavailable")
            }
        }

        private fun encodePublic(key: ECPublicKey): ByteArray {
            fun coordinate(value: java.math.BigInteger): ByteArray {
                val bytes = value.toByteArray()
                val unsigned = if (bytes.size == 33 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, 33) else bytes
                require(unsigned.size <= 32)
                return ByteArray(32 - unsigned.size) + unsigned
            }
            return byteArrayOf(4) + coordinate(key.w.affineX) + coordinate(key.w.affineY)
        }

        /** Strict short-form DER parser: P-256 signatures are always <128 bytes. */
        internal fun derToP1363(der: ByteArray): ByteArray {
            val input = ByteBuffer.wrap(der)
            fun read(): Int { require(input.hasRemaining()); return input.get().toInt() and 255 }
            require(read() == 0x30 && read() == input.remaining()) { "Malformed ECDSA sequence" }
            fun integer(): ByteArray {
                require(read() == 0x02)
                val size = read()
                require(size in 1..33 && input.remaining() >= size)
                val bytes = ByteArray(size).also { input.get(it) }
                require(bytes[0].toInt() and 0x80 == 0) { "Negative ECDSA integer" }
                val stripped = if (size > 1 && bytes[0] == 0.toByte()) {
                    require(bytes[1].toInt() and 0x80 != 0) { "Non-canonical ECDSA integer" }
                    bytes.copyOfRange(1, size)
                } else bytes
                require(stripped.size <= 32)
                return ByteArray(32 - stripped.size) + stripped
            }
            val result = integer() + integer()
            require(!input.hasRemaining())
            return result
        }
    }
}
