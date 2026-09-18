package ai.hai.jacs.platform

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** Runs on a host JVM. Android Keystore/biometric operations are not simulated. */
fun main() {
    val keyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    repeat(32) { index ->
        val message = "JACS Android DER conversion $index".toByteArray()
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(message)
            sign()
        }
        val raw = JacsKeystoreSigner.derToP1363(der)
        check(raw.size == 64)
        // Verify with the JVM's independent P1363 verifier, without a reverse
        // conversion that could accidentally share the same encoding bug.
        check(Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initVerify(keyPair.public)
            update(message)
            verify(raw)
        })
    }
    val malformed = listOf(
        byteArrayOf(),
        byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x80.toByte(), 0x02, 0x01, 0x01), // negative r
        byteArrayOf(0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01), // redundant zero
        byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00), // trailing byte
        byteArrayOf(0x30, 0x81.toByte(), 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01), // long length
    )
    malformed.forEach { input ->
        try {
            JacsKeystoreSigner.derToP1363(input)
            error("Malformed DER was accepted")
        } catch (_: IllegalArgumentException) {
            // Expected rejection.
        }
    }
    println("PASS: 32 independently verified ES256 conversions and 5 malformed-DER rejections")
}
