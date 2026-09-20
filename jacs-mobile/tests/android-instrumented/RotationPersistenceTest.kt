package ai.hai.jacs.platform

import ai.hai.jacs.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Real Rust + Android AtomicFile interruption regression. OS biometric positive
 * authorization is deliberately not simulated; it remains a device gate. */
@RunWith(AndroidJUnit4::class)
class RotationPersistenceTest {
    @Test fun persistedCandidateSurvivesReopenAndAtomicPromotionKeepsOldUntilAcceptance() {
        val directory = File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir,
            "rotation-${UUID.randomUUID()}").apply { mkdirs() }
        val password = "android-rotation-test-local-envelope-secret"
        val old = MobileAgent.createHuman()
        var active: MobileAgent? = null
        try {
            val original = old.exportEncryptedAgent(password)
            val candidate = old.prepareKeyRotation(password)
            // Synthetic wrapped-secret bytes exercise the file container only.
            val wrapped = JacsKeystore.WrappedMaterial(materialToJson(original), ByteArray(45) { 1 })
            EncryptedRecordStore(directory, "test").use { records ->
                records.writeNew(wrapped)
                records.replace(wrapped.copy(pendingMaterialJson = materialToJson(candidate)))
                try { records.replace(wrapped.copy(materialJson = "")); fail("invalid write accepted") }
                catch (_: IllegalArgumentException) { }
                assertEquals(materialToJson(original), records.read().materialJson)
            }
            old.clearSecrets()
            EncryptedRecordStore(directory, "test").use { records ->
                val persisted = records.read()
                assertEquals(materialToJson(candidate), persisted.pendingMaterialJson)
                val agent = MobileAgent.importEncryptedAgent(materialFromJson(persisted.materialJson), password)
                active = agent
                assertEquals(original.agentJson, agent.exportAgentJson())
                val resumed = materialFromJson(persisted.pendingMaterialJson!!)
                assertEquals(candidate.agentJson, agent.validateKeyRotation(resumed, password))
                val proof = agent.signRotationDocumentJson(resumed, password, "{\"purpose\":\"possession\"}")
                assertTrue(verifyWithKey(proof, candidate.publicKey, MobileAlgorithm.PQ2025).valid)
                val backup = agent.exportRotationRecovery(resumed, password)
                assertEquals(candidate.agentJson, verifyRecovery(backup.material, backup.code,
                    JSONObject(candidate.agentJson).getString("jacsId"), candidate.publicKey, MobileAlgorithm.PQ2025))
                try { agent.commitKeyRotation(resumed, password, original.agentJson, original.publicKey); fail("wrong pins accepted") }
                catch (_: MobileException) { }
                assertEquals(original.agentJson, agent.exportAgentJson())
                agent.commitKeyRotation(resumed, password, candidate.agentJson, candidate.publicKey)
                // Model interrupted response: stored old/candidate can reconcile first.
                assertEquals(materialToJson(original), records.read().materialJson)
                records.replace(persisted.copy(materialJson = materialToJson(candidate), pendingMaterialJson = null))
                assertEquals(candidate.agentJson, agent.commitKeyRotation(resumed, password, candidate.agentJson, candidate.publicKey))
            }
            EncryptedRecordStore(directory, "test").use { records ->
                assertEquals(materialToJson(candidate), records.read().materialJson)
                assertNull(records.read().pendingMaterialJson)
            }
        } finally {
            active?.clearSecrets(); active?.close(); old.clearSecrets(); old.close(); directory.deleteRecursively()
        }
    }

    @Test fun cancellationWinningBeforeDurableMutationPreservesStage() {
        val state = JacsVaultState<String>()
        val ticket = state.begin(false)
        var mutated = false
        assertTrue(state.cancel(ticket))
        try { state.mutate(ticket) { mutated = true }; fail("cancelled mutation accepted") }
        catch (error: JacsVaultException) { assertEquals(JacsVaultException.Code.CANCELLED, error.code) }
        assertFalse(mutated)
    }
}
