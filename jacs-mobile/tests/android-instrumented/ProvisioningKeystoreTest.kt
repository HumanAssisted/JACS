package ai.hai.jacs.platform

import ai.hai.jacs.*
import android.content.Intent
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Real AndroidKeyStore policy and persistence. Positive authorization is opt-in:
 * run with -e jacsSyntheticBiometric true on an explicitly owned, enrolled emulator
 * and supply its fingerprint externally. No test manufactures authentication tokens.
 */
@RunWith(AndroidJUnit4::class)
class ProvisioningKeystoreTest {
    private fun enrolled() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val manager = context.getSystemService(BiometricManager::class.java)
        assumeTrue("Strong biometrics must be enrolled", manager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS)
    }
    private fun withAlias(test: (String, JacsKeystore, KeyStore) -> Unit) {
        val alias = "jacs-provision-test-${UUID.randomUUID()}"
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try { test(alias, JacsKeystore(alias), store) }
        finally { store.deleteEntry(alias); store.deleteEntry("$alias.hmac-v2") }
    }
    private fun assertCode(code: JacsVaultException.Code, action: () -> Unit) {
        try { action(); fail("Expected $code") }
        catch (error: JacsVaultException) { assertEquals(code, error.code) }
    }

    @Test fun createsNonexportableStrongPerUseHmacAndCryptoObject() {
        enrolled()
        withAlias { alias, vault, store ->
            val operation = vault.prepareProvision()
            val key = vault.validatedDerivationKey()
            val info = SecretKeyFactory.getInstance("HmacSHA256", "AndroidKeyStore")
                .getKeySpec(key, KeyInfo::class.java) as KeyInfo
            assertEquals("HmacSHA256", key.algorithm)
            assertNull("Root bytes must never be exportable", key.encoded)
            assertEquals(256, info.keySize)
            assertEquals(KeyProperties.ORIGIN_GENERATED, info.origin)
            assertEquals(KeyProperties.PURPOSE_SIGN, info.purposes)
            assertEquals(setOf(KeyProperties.DIGEST_SHA256), info.digests.toSet())
            assertTrue(info.isUserAuthenticationRequired)
            assertEquals(KeyProperties.AUTH_BIOMETRIC_STRONG, info.userAuthenticationType)
            assertTrue(info.userAuthenticationValidityDurationSeconds in -1..0)
            assertTrue(info.isInvalidatedByBiometricEnrollment)
            assertFalse(info.isUserAuthenticationValidWhileOnBody)
            assertTrue(store.containsAlias("$alias.hmac-v2"))
            assertFalse("New provisioning must not create a legacy AES key", store.containsAlias(alias))
            assertEquals(33, operation.descriptor().size)
            assertEquals(2.toByte(), operation.descriptor()[0])
            assertSame(operation.mac, operation.cryptoObject().mac)
            assertTrue(operation.matches(operation.cryptoObject()))
            assertFalse(operation.matches(null))
            val other = vault.prepareOpen(operation.descriptor()) as JacsKeystore.Authentication.Derive
            assertFalse("Another operation cannot authorize this one", operation.matches(other.cryptoObject()))
        }
    }

    @Test fun deniesUnauthenticatedDerivationWithoutCallingConsumer() {
        enrolled()
        assumeTrue("Typed platform denial classification requires API33", Build.VERSION.SDK_INT >= 33)
        withAlias { _, vault, _ ->
            val operation = vault.prepareProvision()
            var called = false
            try {
                vault.withProvisionPassword(operation) { called = true }
                fail("Unauthenticated Keystore MAC succeeded")
            } catch (error: Exception) {
                val causes = generateSequence(error as Throwable?) { it.cause }.toList()
                assertTrue("Expected authentication denial, not another platform failure: $error",
                    causes.any { it is UserNotAuthenticatedException ||
                        (it is android.security.KeyStoreException && it.requiresUserAuthentication()) })
            }
            assertFalse(called)
        }
    }

    @Test fun rejectsWeakExistingRootWithoutReplacingItsMaterial() {
        withAlias { alias, vault, store ->
            val key = KeyGenerator.getInstance("HmacSHA256", "AndroidKeyStore").run {
                init(KeyGenParameterSpec.Builder("$alias.hmac-v2", KeyProperties.PURPOSE_SIGN)
                    .setKeySize(256).setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false).build())
                generateKey()
            }
            val challenge = "public key continuity probe".toByteArray()
            val before = Mac.getInstance("HmacSHA256").run { init(key); doFinal(challenge) }
            assertCode(JacsVaultException.Code.KEY_POLICY) { vault.prepareProvision() }
            assertCode(JacsVaultException.Code.KEY_POLICY) { vault.prepareOpen(byteArrayOf(2) + ByteArray(32)) }
            val retained = store.getKey("$alias.hmac-v2", null)
            val after = Mac.getInstance("HmacSHA256").run { init(retained); doFinal(challenge) }
            assertArrayEquals("Rejected root must remain byte-for-byte the same key", before, after)
        }
    }

    @Test fun missingRootAndMalformedDescriptorNeverGenerateKeys() {
        withAlias { alias, vault, store ->
            assertCode(JacsVaultException.Code.KEY_INVALIDATED) { vault.prepareOpen(byteArrayOf(2) + ByteArray(32)) }
            for (descriptor in listOf(byteArrayOf(), byteArrayOf(2), byteArrayOf(2) + ByteArray(33),
                byteArrayOf(3) + ByteArray(32))) {
                assertCode(JacsVaultException.Code.INVALID_RECORD) { vault.prepareOpen(descriptor) }
            }
            assertFalse(store.containsAlias("$alias.hmac-v2"))
            assertFalse(store.containsAlias(alias))
        }
    }

    @Test fun authenticatedProvisionAndPersistedReopenUseSameKeyWithFreshPrompt() {
        assumeTrue("Explicit task emulator authorization required",
            InstrumentationRegistry.getArguments().getString("jacsSyntheticBiometric") == "true")
        enrolled()
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity = instrumentation.startActivitySync(Intent(instrumentation.targetContext,
            VaultRecoveryTestActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as VaultRecoveryTestActivity
        assertTrue(activity.focused.await(10, TimeUnit.SECONDS))
        val directory = File(activity.noBackupFilesDir, "provision-${UUID.randomUUID()}").apply { mkdirs() }
        try {
            withAlias { alias, vault, _ ->
                val agent = MobileAgent.createHuman()
                try {
                    val identity = agent.exportAgentJson()
                    val publicKey = agent.publicKey()
                    val auth = vault.prepareProvision()
                    authenticate(activity, auth)
                    val record = vault.withProvisionPassword(auth) { password ->
                        JacsKeystore.WrappedMaterial(materialToJson(agent.exportEncryptedAgent(password)), auth.descriptor())
                    }
                    EncryptedRecordStore(directory, "provision").use { it.writeNew(record) }
                    agent.clearSecrets()
                    EncryptedRecordStore(directory, "provision").use { records ->
                        val persisted = records.read()
                        assertArrayEquals(record.wrappedSecret, persisted.wrappedSecret)
                        val reopenedVault = JacsKeystore(alias)
                        val reopen = reopenedVault.prepareOpen(persisted.wrappedSecret)
                        authenticate(activity, reopen)
                        val restored = reopenedVault.open(persisted, reopen)
                        try {
                            assertEquals(identity, restored.exportAgentJson())
                            val proof = restored.signDocumentJson("{\"purpose\":\"instrumented-reopen\"}")
                            assertTrue(verifyWithKey(proof, publicKey, MobileAlgorithm.PQ2025).valid)
                        } finally { restored.clearSecrets(); restored.close() }
                    }
                } finally { agent.clearSecrets(); agent.close() }
            }
        } finally { directory.deleteRecursively(); instrumentation.runOnMainSync { activity.finish() } }
    }

    @Test fun deletingVersionTwoRecordPreservesAnotherOwnersSuffixedRoot() {
        enrolled()
        withAlias { alias, first, store ->
            val second = JacsKeystore("$alias.hmac-v2")
            try {
                first.prepareProvision()
                second.prepareProvision()
                assertCode(JacsVaultException.Code.KEY_POLICY) {
                    second.deleteRecordKey(byteArrayOf(1) + ByteArray(32))
                }
                assertEquals("HmacSHA256", first.validatedDerivationKey().algorithm)
                assertEquals("HmacSHA256", second.validatedDerivationKey().algorithm)
                second.deleteRecordKey(byteArrayOf(2) + ByteArray(32))
                assertTrue(store.containsAlias("$alias.hmac-v2"))
                assertEquals("HmacSHA256", first.validatedDerivationKey().algorithm)
                assertFalse(store.containsAlias("$alias.hmac-v2.hmac-v2"))
                // Legacy deletion must not mistake the first owner's HMAC for AES.
                assertCode(JacsVaultException.Code.KEY_POLICY) { second.deleteWrappingKey() }
                assertEquals("HmacSHA256", first.validatedDerivationKey().algorithm)
            } finally { store.deleteEntry("$alias.hmac-v2.hmac-v2") }
        }
    }

    @Test fun deletingLegacyRecordPreservesNewOwnerRootAndUnknownOrphans() {
        enrolled()
        withAlias { alias, first, store ->
            val second = JacsKeystore("$alias.hmac-v2")
            try {
                first.ensureWrappingKey()
                first.prepareProvision()
                second.prepareProvision()
                first.deleteRecordKey(byteArrayOf(1) + ByteArray(60))
                assertFalse(store.containsAlias(alias))
                assertEquals("HmacSHA256", first.validatedDerivationKey().algorithm)
                assertEquals("HmacSHA256", second.validatedDerivationKey().algorithm)
            } finally { store.deleteEntry("$alias.hmac-v2.hmac-v2") }
        }
    }

    private class Capture<T> : JacsVaultCallback<T> {
        val done = CountDownLatch(1)
        var value: T? = null
        var error: JacsVaultException? = null
        var calls = 0
        override fun onSuccess(value: T) { this.value = value; calls++; done.countDown() }
        override fun onError(error: JacsVaultException) { this.error = error; calls++; done.countDown() }
        fun await(): T {
            assertTrue("Vault callback timed out", done.await(50, TimeUnit.SECONDS))
            assertNull("Vault must succeed", error)
            assertEquals(1, calls)
            return value!!
        }
    }

    private fun startHost(): VaultRecoveryTestActivity {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity = instrumentation.startActivitySync(Intent(instrumentation.targetContext,
            VaultRecoveryTestActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as VaultRecoveryTestActivity
        assertTrue(activity.focused.await(10, TimeUnit.SECONDS))
        return activity
    }

    private fun unauthenticatedKey(entry: String, algorithm: String) {
        val spec = if (algorithm == "AES") KeyGenParameterSpec.Builder(entry,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT).setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build()
        else KeyGenParameterSpec.Builder(entry, KeyProperties.PURPOSE_SIGN).setKeySize(256)
            .setDigests(KeyProperties.DIGEST_SHA256).build()
        KeyGenerator.getInstance(algorithm, "AndroidKeyStore").run { init(spec); generateKey() }
    }

    /** Public delete with no record. Ownership is the alias with its key algorithm, not the
     * key policy, so unauthenticated keys stand in for orphans and no enrollment is needed. */
    @Test fun deletingWithoutRecordRemovesOwnOrphansAndKeepsOtherOwnersKeys() {
        // Each alias extends the previous one by ".hmac-v2". The vault under test is
        // names[1]: its parent's root and its child's legacy key can occupy its own names.
        val base = "jacs-orphan-test-${UUID.randomUUID()}"
        val names = (0..3).map { base + ".hmac-v2".repeat(it) }
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity = startHost()
        var vault: JacsBiometricVault? = null
        fun delete() {
            val deleted = Capture<Unit>()
            instrumentation.runOnMainSync { vault!!.delete(deleted) }
            deleted.await()
        }
        try {
            instrumentation.runOnMainSync { vault = JacsBiometricVault(activity, names[1]) }
            unauthenticatedKey(names[0], "AES")        // parent's legacy key
            unauthenticatedKey(names[1], "AES")        // own legacy key
            unauthenticatedKey(names[2], "HmacSHA256") // own orphan root
            unauthenticatedKey(names[3], "HmacSHA256") // child's root
            delete()
            assertFalse("Own legacy key must be removed", store.containsAlias(names[1]))
            assertFalse("Own orphan root must be removed", store.containsAlias(names[2]))
            assertEquals("AES", store.getKey(names[0], null)?.algorithm)
            assertEquals("HmacSHA256", store.getKey(names[3], null)?.algorithm)
            unauthenticatedKey(names[1], "HmacSHA256") // parent's root under our legacy name
            unauthenticatedKey(names[2], "AES")        // child's legacy key under our root name
            delete()
            assertEquals("HmacSHA256", store.getKey(names[1], null)?.algorithm)
            assertEquals("AES", store.getKey(names[2], null)?.algorithm)
        } finally {
            instrumentation.runOnMainSync { vault?.close(); activity.finish() }
            names.forEach { store.deleteEntry(it) }
        }
    }

    @Test fun publicCreateAfterOrphanRootCleanupUsesFreshRoot() {
        assumeTrue("Explicit task emulator authorization required",
            InstrumentationRegistry.getArguments().getString("jacsSyntheticBiometric") == "true")
        enrolled()
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity = startHost()
        val alias = "jacs-orphan-create-${UUID.randomUUID()}"
        val root = JacsKeystore.rootAlias(alias)
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        var vault: JacsBiometricVault? = null
        fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
        try {
            JacsKeystore(alias).prepareProvision() // the root an interrupted ceremony leaves
            assertTrue(store.containsAlias(root))
            main { vault = JacsBiometricVault(activity, alias) }
            val cleared = Capture<Unit>()
            main { vault!!.delete(cleared) }
            cleared.await()
            assertFalse("Delete without a record must remove the orphan root", store.containsAlias(root))
            val created = Capture<JacsVaultIdentity>()
            main { vault!!.createHuman("Create after orphan cleanup test", created) }
            val identity = created.await()
            assertEquals("HmacSHA256", JacsKeystore(alias).validatedDerivationKey().algorithm)
            val signed = Capture<String>()
            main { vault!!.signDocumentJson("{\"purpose\":\"after-orphan-cleanup\"}", signed) }
            val key = java.util.Base64.getDecoder().decode(identity.publicKeyBase64)
            assertTrue(verifyWithKey(signed.await(), key, MobileAlgorithm.PQ2025).valid)
            val erased = Capture<Unit>()
            main { vault!!.delete(erased) }
            erased.await()
            assertFalse("Deleting the new record must remove its root", store.containsAlias(root))
        } finally {
            main { vault?.close(); activity.finish() }
            store.deleteEntry(root)
        }
    }

    private val enrollmentChangePhase get() =
        InstrumentationRegistry.getArguments().getString("jacsEnrollmentChangePhase")
    private val enrollmentChangeAlias = "jacs-enrollment-change-test"

    /** Opt-in phase 1 of 2: -e jacsEnrollmentChangePhase 1. A cancelled public create leaves a
     * valid root and no record. Keep this APK installed, enroll another biometric, run phase 2. */
    @Test fun enrollmentChangePhase1CancelledCreateLeavesRoot() {
        assumeTrue("Opt-in enrollment change, phase 1", enrollmentChangePhase == "1")
        enrolled()
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity = startHost()
        val root = JacsKeystore.rootAlias(enrollmentChangeAlias)
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        var vault: JacsBiometricVault? = null
        fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
        try {
            main { vault = JacsBiometricVault(activity, enrollmentChangeAlias) }
            val cleared = Capture<Unit>()
            main { vault!!.delete(cleared) } // whatever an earlier run left
            cleared.await()
            val cancelled = Capture<JacsVaultIdentity>()
            main { vault!!.createHuman("Enrollment change test", cancelled).cancel() }
            assertTrue(cancelled.done.await(10, TimeUnit.SECONDS))
            assertEquals(JacsVaultException.Code.CANCELLED, cancelled.error?.code)
            // The serial worker runs this after the cancelled create's provisioning step.
            val inspected = Capture<JacsVaultInspection>()
            main { vault!!.inspect(inspected) }
            assertEquals(JacsVaultRecordState.ABSENT, inspected.await().state)
            assertTrue("A cancelled create leaves its root", store.containsAlias(root))
            // Still valid: only the enrollment change between phases invalidates it.
            Mac.getInstance("HmacSHA256").init(JacsKeystore(enrollmentChangeAlias).validatedDerivationKey())
        } finally { main { vault?.close(); activity.finish() } }
    }

    /** Opt-in phase 2 of 2: -e jacsEnrollmentChangePhase 2, after the enrollment change. The
     * orphan root is permanently invalidated; create replaces it before its only prompt. */
    @Test fun enrollmentChangePhase2ReplacesInvalidatedRootBeforeOnePrompt() {
        assumeTrue("Opt-in enrollment change, phase 2", enrollmentChangePhase == "2")
        enrolled()
        val root = JacsKeystore.rootAlias(enrollmentChangeAlias)
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("Run phase 1 first", store.containsAlias(root))
        assertThrows("Change enrollment after phase 1", KeyPermanentlyInvalidatedException::class.java) {
            Mac.getInstance("HmacSHA256").init(store.getKey(root, null) as SecretKey)
        }
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity = startHost()
        val focusLosses = AtomicInteger() // each prompt is a focused system window
        var vault: JacsBiometricVault? = null
        fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
        try {
            main {
                vault = JacsBiometricVault(activity, enrollmentChangeAlias)
                activity.window.decorView.viewTreeObserver.addOnWindowFocusChangeListener {
                    if (!it) focusLosses.incrementAndGet()
                }
            }
            val inspected = Capture<JacsVaultInspection>()
            main { vault!!.inspect(inspected) }
            assertEquals(JacsVaultRecordState.ABSENT, inspected.await().state)
            val created = Capture<JacsVaultIdentity>()
            main { vault!!.createHuman("Create after enrollment change test", created) }
            val identity = created.await()
            assertEquals("Exactly one prompt", 1, focusLosses.get())
            // The replacement root is valid under the new enrollment.
            Mac.getInstance("HmacSHA256").init(JacsKeystore(enrollmentChangeAlias).validatedDerivationKey())
            val signed = Capture<String>()
            main { vault!!.signDocumentJson("{\"purpose\":\"after-enrollment-change\"}", signed) }
            val key = java.util.Base64.getDecoder().decode(identity.publicKeyBase64)
            assertTrue(verifyWithKey(signed.await(), key, MobileAlgorithm.PQ2025).valid)
            val erased = Capture<Unit>()
            main { vault!!.delete(erased) }
            erased.await()
            assertFalse("Deleting the new record must remove its root", store.containsAlias(root))
        } finally { main { vault?.close(); activity.finish() } }
    }

    @Test fun publicVaultProvisionReadbackAndFreshUnlockRetainIdentity() {
        assumeTrue("Explicit task emulator authorization required",
            InstrumentationRegistry.getArguments().getString("jacsSyntheticBiometric") == "true")
        enrolled()
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity = instrumentation.startActivitySync(Intent(instrumentation.targetContext,
            VaultRecoveryTestActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as VaultRecoveryTestActivity
        assertTrue(activity.focused.await(10, TimeUnit.SECONDS))
        val alias = "jacs-public-provision-${UUID.randomUUID()}"
        lateinit var vault: JacsBiometricVault
        fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
        main { vault = JacsBiometricVault(activity, alias) }
        try {
            val created = Capture<JacsVaultIdentity>()
            main { vault.createHuman("Provision readback test", created) }
            val initial = created.await()
            assertTrue(vault.isUnlocked())
            val first = Capture<String>()
            main { vault.signDocumentJson("{\"purpose\":\"after-persisted-provision\"}", first) }
            val key = java.util.Base64.getDecoder().decode(initial.publicKeyBase64)
            assertTrue(verifyWithKey(first.await(), key, MobileAlgorithm.PQ2025).valid)
            main { vault.lock() }
            assertFalse(vault.isUnlocked())
            val locked = Capture<String>()
            main { vault.signDocumentJson("{}", locked) }
            assertTrue(locked.done.await(10, TimeUnit.SECONDS))
            assertEquals(JacsVaultException.Code.LOCKED, locked.error?.code)
            // Close/recreate the public vault to ensure a new record owner/session.
            main { vault.close(); vault = JacsBiometricVault(activity, alias) }
            val reopened = Capture<JacsVaultIdentity>()
            main { vault.unlock("Reopen persisted identity test", reopened) }
            assertEquals(initial, reopened.await())
            val fresh = Capture<String>()
            main { vault.signDocumentJson("{\"purpose\":\"after-fresh-unlock\"}", fresh) }
            assertTrue(verifyWithKey(fresh.await(), key, MobileAlgorithm.PQ2025).valid)
            main { vault.lock() }
        } finally {
            main { vault.close(); activity.finish() }
            EncryptedRecordStore(activity.applicationContext.noBackupFilesDir, alias).use { it.delete() }
            JacsKeystore(alias).deleteRecordKey(byteArrayOf(2) + ByteArray(32))
        }
    }

    private fun authenticate(activity: VaultRecoveryTestActivity, auth: JacsKeystore.Authentication) {
        val done = CountDownLatch(1)
        var result: BiometricPrompt.CryptoObject? = null
        var error: String? = null
        val cancellation = CancellationSignal()
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            BiometricPrompt.Builder(activity).setTitle("JACS provisioning test")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButton("Cancel", activity.mainExecutor) { _, _ -> error = "cancelled"; done.countDown() }
                .build().authenticate(auth.cryptoObject(), cancellation, activity.mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(value: BiometricPrompt.AuthenticationResult) {
                            result = value.cryptoObject; done.countDown()
                        }
                        override fun onAuthenticationError(code: Int, message: CharSequence) {
                            error = "error $code"; done.countDown()
                        }
                    })
        }
        try {
            assertTrue("Biometric authorization timed out", done.await(45, TimeUnit.SECONDS))
            assertNull(error)
            assertTrue("Callback must return this exact MAC operation", auth.matches(result))
        } finally { cancellation.cancel() }
    }
}
