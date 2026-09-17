package ai.hai.jacs.platform

import java.util.concurrent.CountDownLatch

private fun expectCode(code: JacsVaultException.Code, operation: () -> Unit) {
    try { operation(); error("Expected $code") }
    catch (error: JacsVaultException) { check(error.code == code) }
}

/** Test production state coordination independently of Android prompt stubs. */
fun main() {
    var cases = 0
    run {
        val state = JacsVaultState<String>()
        expectCode(JacsVaultException.Code.LOCKED) { state.begin(true) }
        val ticket = state.begin(false, true)
        expectCode(JacsVaultException.Code.BUSY) { state.begin(false) }
        val cipher = Any()
        check(state.bindCipher(ticket, cipher))
        check(!state.authenticate(ticket, null))
        check(!state.authenticate(ticket, Any()))
        check(state.authenticate(ticket, cipher))
        check(!state.authenticate(ticket, cipher)) // callback cannot consume twice
        check(state.install(ticket, "secret"))
        check(state.finish(ticket))
        check(!state.finish(ticket))
        check(!state.cancel(ticket)) // completed operation cannot cancel a later session
        val signing = state.begin(true)
        check(state.session(signing) == "secret")
        val invalidated = state.invalidate()
        check(invalidated.session == "secret" && invalidated.ticket === signing)
        check(!state.isUnlocked() && !state.finish(signing))
        cases++
    }
    for (stage in 0..2) {
        val state = JacsVaultState<String>()
        val ticket = state.begin(false, true)
        val cipher = Any()
        if (stage >= 1) check(state.bindCipher(ticket, cipher))
        if (stage >= 2) check(state.authenticate(ticket, cipher))
        check(state.cancel(ticket))
        check(!state.current(ticket))
        check(!state.authenticate(ticket, cipher))
        check(!state.install(ticket, "late unlocked handle"))
        check(!state.finish(ticket))
        state.invalidate()
        val next = state.begin(false, true)
        check(!state.install(ticket, "stale generation"))
        check(!state.cancel(ticket))
        check(state.current(next))
        cases++
    }
    run {
        val state = JacsVaultState<String>()
        val ticket = state.begin(false, true)
        val cipher = Any()
        state.bindCipher(ticket, cipher); state.authenticate(ticket, cipher)
        state.invalidate(true)
        check(!state.install(ticket, "late completion after close"))
        expectCode(JacsVaultException.Code.CLOSED) { state.begin(false) }
        cases++
    }
    repeat(250) {
        val state = JacsVaultState<String>()
        val ticket = state.begin(false, true)
        val cipher = Any()
        state.bindCipher(ticket, cipher); state.authenticate(ticket, cipher)
        val start = CountDownLatch(1)
        val cancelled = Thread { start.await(); state.invalidate() }
        val completed = Thread { start.await(); state.install(ticket, "candidate"); state.finish(ticket) }
        cancelled.start(); completed.start(); start.countDown()
        cancelled.join(); completed.join()
        check(!state.isUnlocked()) { "Cancellation race published a stale session" }
        check(!state.current(ticket))
        cases++
    }
    check(JacsBiometricVault.promptError(7) == JacsVaultException.Code.LOCKOUT)
    check(JacsBiometricVault.promptError(9) == JacsVaultException.Code.PERMANENT_LOCKOUT)
    check(JacsBiometricVault.promptError(10) == JacsVaultException.Code.CANCELLED)
    check(JacsBiometricVault.promptError(11) == JacsVaultException.Code.NOT_ENROLLED)
    check(JacsBiometricVault.promptError(1) == JacsVaultException.Code.UNAVAILABLE)
    println("PASS: $cases biometric lifecycle/identity/cancellation cases, including 250 completion races, and typed prompt errors")
}
