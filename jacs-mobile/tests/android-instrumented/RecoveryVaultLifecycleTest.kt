package ai.hai.jacs.platform

import ai.hai.jacs.*
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Real Android vault entry points and release Rust FFI. No biometric token is
 * faked; positive biometric creation/signing remains a physical-device gate. */
@RunWith(AndroidJUnit4::class)
class RecoveryVaultLifecycleTest {
    private class Capture<T> : JacsVaultCallback<T> {
        val done = CountDownLatch(1)
        var value: T? = null
        var error: JacsVaultException? = null
        var calls = 0
        override fun onSuccess(value: T) { this.value = value; calls++; done.countDown() }
        override fun onError(error: JacsVaultException) { this.error = error; calls++; done.countDown() }
        fun await() { assertTrue("vault callback timed out", done.await(20, TimeUnit.SECONDS)) }
    }
    private fun withVault(test: (JacsBiometricVault) -> Unit) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity = instrumentation.startActivitySync(Intent(instrumentation.targetContext,
            VaultRecoveryTestActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as VaultRecoveryTestActivity
        assertTrue(activity.focused.await(10, TimeUnit.SECONDS))
        lateinit var vault: JacsBiometricVault
        instrumentation.runOnMainSync { vault = JacsBiometricVault(activity, "recovery-test-${UUID.randomUUID()}") }
        try { test(vault) } finally { instrumentation.runOnMainSync { vault.close(); activity.finish() } }
    }
    private fun main(action: () -> Unit) = InstrumentationRegistry.getInstrumentation().runOnMainSync(action)

    @Test fun ownedReadbackDoesNotCreateSessionAndClassifiesWrongInputs() = withVault { vault ->
        val inspection = Capture<JacsVaultInspection>()
        main { vault.inspect(inspection) }; inspection.await()
        assertEquals(JacsVaultRecordState.ABSENT, inspection.value?.state)
        assertNull(inspection.value?.identity)
        val description = Capture<MobilePublicIdentity>()
        main { vault.describe(description) }; description.await()
        assertEquals(JacsVaultException.Code.LOCKED, description.error?.code)
        val human = MobileAgent.createHuman()
        try {
            val identity = human.exportAgentJson()
            val id = JSONObject(identity).getString("jacsId")
            val backup = human.exportRecovery()
            val wire = materialToJson(backup.material)
            val valid = Capture<String>()
            main { vault.verifyRecovery(wire, backup.code, id, human.publicKey(), valid) }
            valid.await()
            assertNull(valid.error); assertEquals(identity, valid.value)
            assertFalse(vault.isUnlocked())
            for ((material, code, expectedId, expectedError) in listOf(
                listOf(wire, "bad-paste", id, JacsVaultException.Code.INVALID_RECOVERY_CODE),
                listOf(wire, generateRecoveryCode(), id, JacsVaultException.Code.INVALID_RECOVERY_CODE),
                listOf(wire, backup.code, "other-id", JacsVaultException.Code.IDENTITY_MISMATCH),
                listOf("{}", backup.code, id, JacsVaultException.Code.MALFORMED_MATERIAL)
            )) {
                val result = Capture<String>()
                main { vault.verifyRecovery(material as String, code as String, expectedId as String, human.publicKey(), result) }
                result.await(); assertEquals(expectedError, result.error?.code)
                assertFalse(vault.isUnlocked())
            }
            val locked = Capture<JacsEncryptedRecovery>()
            main { vault.createRecovery(locked) }; locked.await()
            assertEquals(JacsVaultException.Code.LOCKED, locked.error?.code)
            val signing = Capture<String>()
            main { vault.signDocumentJson("{}", signing) }; signing.await()
            assertEquals(JacsVaultException.Code.LOCKED, signing.error?.code)
            val badPaste = Capture<JacsVaultIdentity>()
            main { vault.receiveRecovery(wire, "bad-paste", id, human.publicKey(), "Restore", badPaste) }
            badPaste.await(); assertEquals(JacsVaultException.Code.INVALID_RECOVERY_CODE, badPaste.error?.code)
        } finally { human.clearSecrets(); human.close() }
    }

    @Test fun cancelledAndClosedReadbackNeverDeliversLateSuccess() = withVault { vault ->
        val human = MobileAgent.createHuman()
        try {
            val backup = human.exportRecovery()
            val id = JSONObject(human.exportAgentJson()).getString("jacsId")
            val result = Capture<String>()
            main {
                vault.verifyRecovery(materialToJson(backup.material), backup.code, id, human.publicKey(), result).cancel()
            }
            result.await(); assertEquals(JacsVaultException.Code.CANCELLED, result.error?.code)
            val closed = Capture<String>()
            main {
                vault.verifyRecovery(materialToJson(backup.material), backup.code, id, human.publicKey(), closed)
                vault.close()
            }
            closed.await(); assertEquals(JacsVaultException.Code.CLOSED, closed.error?.code)
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            assertEquals(1, result.calls); assertEquals(1, closed.calls)
        } finally { human.clearSecrets(); human.close() }
    }

    @Test fun cancelledHumanCreationDoesNotOpenSession() = withVault { vault ->
        val result = Capture<JacsVaultIdentity>()
        main { vault.createHuman("Set up", result).cancel() }
        result.await()
        assertEquals(JacsVaultException.Code.CANCELLED, result.error?.code)
        assertFalse(vault.isUnlocked())
    }
}
