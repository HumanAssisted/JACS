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
            // Keeping the session open never opens one.
            val keptOpen = Capture<JacsEncryptedRecovery>()
            main { vault.createRecovery(keptOpen, keepOpen = true) }; keptOpen.await()
            assertEquals(JacsVaultException.Code.LOCKED, keptOpen.error?.code)
            val keptOpenTransfer = Capture<JacsEncryptedTransfer>()
            main { vault.createTransfer(keptOpenTransfer, keepOpen = true) }; keptOpenTransfer.await()
            assertEquals(JacsVaultException.Code.LOCKED, keptOpenTransfer.error?.code)
            assertFalse(vault.isUnlocked())
            val signing = Capture<String>()
            main { vault.signDocumentJson("{}", signing) }; signing.await()
            assertEquals(JacsVaultException.Code.LOCKED, signing.error?.code)
            val preparedSigning = Capture<String>()
            main { vault.signPreparedDocumentJson("{}", preparedSigning) }; preparedSigning.await()
            assertEquals(JacsVaultException.Code.LOCKED, preparedSigning.error?.code)
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

    private class Installed(val agentJson: String, val publicKey: ByteArray) {
        val jacsId: String = JSONObject(agentJson).getString("jacsId")
    }

    /** CI has no enrolled biometrics. This installs a live release-Rust session through
     * the vault's own state machine, in the order a successful prompt does, with no
     * prompt, Keystore key or authentication token. What follows an unlock then runs
     * as real vault code. The vault owns and clears the agent once it is installed. */
    private fun installSession(vault: JacsBiometricVault): Installed {
        @Suppress("UNCHECKED_CAST")
        val state = JacsBiometricVault::class.java.getDeclaredField("state")
            .apply { isAccessible = true }.get(vault) as JacsVaultState<MobileAgent>
        val agent = MobileAgent.createHuman()
        var owned = false
        try {
            val installed = Installed(agent.exportAgentJson(), agent.publicKey())
            val ticket = state.begin(false, true)
            val operation = Any()
            assertTrue(state.bindOperation(ticket, operation) && state.authenticate(ticket, operation))
            owned = state.install(ticket, agent)
            assertTrue("Session installed", owned && state.finish(ticket) && vault.isUnlocked())
            return installed
        } finally { if (!owned) { agent.clearSecrets(); agent.close() } }
    }

    private fun assertRecovers(result: Capture<JacsEncryptedRecovery>, identity: Installed) {
        assertNull(result.error)
        val backup = result.value!!
        assertEquals(identity.agentJson, verifyRecovery(materialFromJson(backup.materialJson), backup.code,
            identity.jacsId, identity.publicKey, MobileAlgorithm.PQ2025))
    }

    private fun assertTransfers(result: Capture<JacsEncryptedTransfer>, identity: Installed) {
        assertNull(result.error)
        val transfer = result.value!!
        val received = MobileAgent.importPinned(materialFromJson(transfer.materialJson), transfer.code,
            identity.jacsId, identity.publicKey, MobileAlgorithm.PQ2025)
        try { assertEquals(identity.agentJson, received.exportAgentJson()) }
        finally { received.clearSecrets(); received.close() }
    }

    @Test fun installedSessionExportsRelockByDefaultAndStayOpenOnlyWhenAsked() = withVault { vault ->
        fun assertLocked() {
            assertFalse(vault.isUnlocked())
            val signing = Capture<String>()
            main { vault.signMessageJson("{}", signing) }; signing.await()
            assertEquals(JacsVaultException.Code.LOCKED, signing.error?.code)
        }
        // The one-argument methods that Java callers get from @JvmOverloads.
        fun javaOverload(name: String) = JacsBiometricVault::class.java.getMethod(name, JacsVaultCallback::class.java)

        // Each default export relocks before its callback, from Kotlin and from Java.
        var identity = installSession(vault)
        val recovery = Capture<JacsEncryptedRecovery>()
        main { vault.createRecovery(recovery) }; recovery.await()
        assertLocked(); assertRecovers(recovery, identity)
        identity = installSession(vault)
        val javaRecovery = Capture<JacsEncryptedRecovery>()
        main { javaOverload("createRecovery").invoke(vault, javaRecovery) }; javaRecovery.await()
        assertLocked(); assertRecovers(javaRecovery, identity)
        identity = installSession(vault)
        val transfer = Capture<JacsEncryptedTransfer>()
        main { vault.createTransfer(transfer) }; transfer.await()
        assertLocked(); assertTransfers(transfer, identity)
        identity = installSession(vault)
        val javaTransfer = Capture<JacsEncryptedTransfer>()
        main { javaOverload("createTransfer").invoke(vault, javaTransfer) }; javaTransfer.await()
        assertLocked(); assertTransfers(javaTransfer, identity)

        // Asked to stay open, both exports leave the same session signing, with no
        // new unlock, until lock().
        identity = installSession(vault)
        val keptRecovery = Capture<JacsEncryptedRecovery>()
        main { vault.createRecovery(keptRecovery, keepOpen = true) }; keptRecovery.await()
        assertNull(keptRecovery.error); assertTrue(vault.isUnlocked())
        val keptTransfer = Capture<JacsEncryptedTransfer>()
        main { vault.createTransfer(keptTransfer, keepOpen = true) }; keptTransfer.await()
        assertNull(keptTransfer.error); assertTrue(vault.isUnlocked())
        val signed = Capture<String>()
        main { vault.signMessageJson("{\"purpose\":\"after-kept-open-exports\"}", signed) }; signed.await()
        assertNull(signed.error)
        assertTrue(verifyWithKey(signed.value!!, identity.publicKey, MobileAlgorithm.PQ2025).valid)
        assertRecovers(keptRecovery, identity); assertTransfers(keptTransfer, identity)
        main { vault.lock() }
        assertLocked()

        // Cancelling a pending kept-open export still ends the session.
        installSession(vault)
        val cancelled = Capture<JacsEncryptedRecovery>()
        main { vault.createRecovery(cancelled, keepOpen = true).cancel() }; cancelled.await()
        assertEquals(JacsVaultException.Code.CANCELLED, cancelled.error?.code)
        assertLocked()
        // The serial worker runs this after the cancelled export, so any late result
        // from that export has reached the main thread before this callback.
        val drained = Capture<JacsVaultInspection>()
        main { vault.inspect(drained) }; drained.await()
        assertEquals(1, cancelled.calls)
    }
}
