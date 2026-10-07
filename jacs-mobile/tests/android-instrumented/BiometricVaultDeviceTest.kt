package ai.hai.jacs.platform

import ai.hai.jacs.MobileAgent
import ai.hai.jacs.MobileAlgorithm
import ai.hai.jacs.materialToJson
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import java.util.UUID
import javax.crypto.KeyGenerator
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Runs against real AndroidKeyStore and app-private Android file APIs.
 * No enrolled user or simulated authentication token is needed for these tests.
 * Successful biometric authorization still requires the separate device exercise.
 */
@RunWith(AndroidJUnit4::class)
class BiometricVaultDeviceTest {
    @Test fun rejectsExistingAesKeyWithoutBiometricPolicy() {
        val alias = "jacs-test-${UUID.randomUUID()}"
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            KeyGenerator.getInstance("AES", "AndroidKeyStore").apply {
                init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(false).build())
                generateKey()
            }
            val wrapper = JacsKeystore(alias)
            assertCode(JacsVaultException.Code.KEY_POLICY) { wrapper.ensureWrappingKey() }
            assertCode(JacsVaultException.Code.KEY_POLICY) { wrapper.prepareProtect() }
            assertCode(JacsVaultException.Code.KEY_POLICY) { wrapper.prepareUnlock(byteArrayOf(1) + ByteArray(60)) }
            assertTrue("Validation must not replace a weaker existing alias", store.containsAlias(alias))
        } finally { store.deleteEntry(alias) }
    }

    @Test fun missingKeyFailsClosedInsteadOfRegeneratingOnUnlock() {
        val alias = "jacs-missing-${UUID.randomUUID()}"
        assertCode(JacsVaultException.Code.KEY_INVALIDATED) {
            JacsKeystore(alias).prepareUnlock(byteArrayOf(1) + ByteArray(60))
        }
    }

    @Test fun persistsOnlyEncryptedRecordAndRejectsReplacementOrTruncation() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = File(context.noBackupFilesDir, "jacs-test-${UUID.randomUUID()}").apply { mkdirs() }
        val agent = MobileAgent.create(MobileAlgorithm.PQ2025)
        val store = EncryptedRecordStore(directory, "record-test")
        try {
            val encrypted = materialToJson(agent.exportEncryptedAgent("test-envelope-password-only"))
            val record = JacsKeystore.WrappedMaterial(encrypted, byteArrayOf(1) + ByteArray(60) { 7 })
            assertCode(JacsVaultException.Code.BUSY) { EncryptedRecordStore(directory, "record-test") }
            store.writeNew(record)
            val restored = store.read()
            assertEquals(encrypted, restored.materialJson)
            assertArrayEquals(record.wrappedSecret, restored.wrappedSecret)
            assertCode(JacsVaultException.Code.ALREADY_EXISTS) { store.writeNew(record) }
            directory.listFiles()!!.single { it.name.endsWith(".bin") }.writeBytes(byteArrayOf(1, 2))
            assertCode(JacsVaultException.Code.INVALID_RECORD) { store.read() }
            store.delete()
            assertCode(JacsVaultException.Code.MISSING_RECORD) { store.read() }
        } finally { store.close(); agent.clearSecrets(); agent.close(); directory.deleteRecursively() }
    }

    private fun assertCode(code: JacsVaultException.Code, operation: () -> Unit) {
        try { operation(); fail("Expected $code") }
        catch (error: JacsVaultException) { assertEquals(code, error.code) }
    }
}
