package ai.hai.jacs.platform

/** Host checks for the two platform representations of per-use authentication.
 * Device tests separately exercise real Keystore creation and policy rejection.
 */
fun main() {
    val cases = listOf(
        -1 to true, // documented KeyInfo representation
        0 to true,  // Android 15 Keystore2 representation
        Int.MIN_VALUE to false,
        -2 to false,
        1 to false,
        15 to false, // a short authentication window is still not per-use
        30 to false,
        300 to false,
        Int.MAX_VALUE to false,
    )
    for ((seconds, expected) in cases) {
        check(isPerUseAuthenticationDuration(seconds) == expected) {
            "Unexpected per-use policy result for duration $seconds"
        }
    }
    println("PASS: ${cases.size} wrapping-key authentication-duration cases")
}
