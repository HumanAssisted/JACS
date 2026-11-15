package ai.hai.jacs.platform

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private fun rejects(code: JacsVaultException.Code, operation: () -> Unit) {
    try { operation(); error("Expected $code") }
    catch (error: JacsVaultException) { check(error.code == code) }
}

/** Real descriptor, readback and state functions; no Android authentication claims. */
fun main() {
    val descriptor = byteArrayOf(2) + ByteArray(32) { it.toByte() }
    val input = JacsKeystore.derivationInput("test.vault", descriptor)
    // Independently computed with Python hashlib/hmac over the documented format.
    val vector = Mac.getInstance("HmacSHA256").apply {
        init(SecretKeySpec(ByteArray(32) { it.toByte() }, "HmacSHA256"))
    }.doFinal(input).joinToString("") { "%02x".format(it.toInt() and 255) }
    check(vector == "a203b1ab90c3dd1ccabadc0821e0e168f85e67f664bc5955e1bb326511e59bf0")
    check(!input.contentEquals(JacsKeystore.derivationInput("test.other", descriptor)))
    val changed = descriptor.copyOf().also { it[32] = 99 }
    check(!input.contentEquals(JacsKeystore.derivationInput("test.vault", changed)))
    for (bad in listOf(byteArrayOf(), byteArrayOf(2), ByteArray(33), byteArrayOf(3) + ByteArray(32), descriptor + 0)) {
        rejects(JacsVaultException.Code.INVALID_RECORD) { JacsKeystore.derivationInput("test.vault", bad) }
        rejects(JacsVaultException.Code.INVALID_RECORD) { JacsKeystore.validateDescriptor(bad) }
    }
    JacsKeystore.validateDescriptor(byteArrayOf(1) + ByteArray(28))
    JacsKeystore.validateDescriptor(descriptor)
    rejects(JacsVaultException.Code.INVALID_RECORD) { JacsKeystore.derivationInput("", descriptor) }

    // A public descriptor cannot be changed through caller-owned byte arrays.
    val mac = Mac.getInstance("HmacSHA256")
    val auth = JacsKeystore.Authentication.Derive(mac, descriptor)
    descriptor[1] = 99
    val frozen = auth.descriptor()
    check(frozen[1] == 0.toByte())
    auth.descriptor().fill(99)
    auth.requireDescriptor(frozen)
    rejects(JacsVaultException.Code.INTEGRITY) { auth.requireDescriptor(descriptor) }
    val expected = JacsKeystore.WrappedMaterial("ciphertext", frozen)
    requireProvisionReadback(expected, expected.copy(wrappedSecret = frozen.copyOf()))
    for (actual in listOf(expected.copy(materialJson = "other"), expected.copy(wrappedSecret = descriptor),
        expected.copy(pendingMaterialJson = "unrequested staged rotation"))) {
        rejects(JacsVaultException.Code.INTEGRITY) { requireProvisionReadback(expected, actual) }
    }

    val state = JacsVaultState<String>()
    val ticket = state.begin(false, true)
    check(state.bindOperation(ticket, mac))
    check(!state.authenticate(ticket, Mac.getInstance("HmacSHA256")))
    check(!state.authenticate(ticket, null))
    check(state.authenticate(ticket, mac))
    check(!state.authenticate(ticket, mac))
    state.invalidate()
    check(!state.install(ticket, "late persisted import"))
    println("PASS: provisioning descriptor isolation, persisted readback corruption, and MAC callback ownership")
}
