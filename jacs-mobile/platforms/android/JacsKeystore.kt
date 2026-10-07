package ai.hai.jacs.platform

import ai.hai.jacs.*
import android.os.Build
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
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/** Default custody path for transferable ML-DSA-87 (pq2025) identities.
 * Biometrics gate the AES wrapping key; ML-DSA signing stays in portable Rust.
 * Android API 30+. All AES operations require a BiometricPrompt CryptoObject.
 * Persist only WrappedMaterial; its secret is encrypted with a non-exportable
 * AndroidKeyStore AES key. The JACS signing key remains transferable ciphertext.
 */
class JacsKeystore(private val alias: String) {
    data class WrappedMaterial(val materialJson: String, val wrappedSecret: ByteArray,
        val pendingMaterialJson: String? = null)
    private val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

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
            // Android reports -1 for authentication on every key use, even
            // though KeyGenParameterSpec expresses that duration as zero.
            if (key.algorithm != KeyProperties.KEY_ALGORITHM_AES || info.keySize != 256 ||
                info.purposes != (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT) ||
                info.blockModes.toSet() != setOf(KeyProperties.BLOCK_MODE_GCM) ||
                info.encryptionPaddings.toSet() != setOf(KeyProperties.ENCRYPTION_PADDING_NONE) ||
                !info.isUserAuthenticationRequired ||
                info.userAuthenticationType != KeyProperties.AUTH_BIOMETRIC_STRONG ||
                info.userAuthenticationValidityDurationSeconds != -1 ||
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

    fun deleteWrappingKey() { store.deleteEntry(alias) }
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
