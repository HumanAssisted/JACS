package ai.hai.jacs.platform

import java.util.concurrent.atomic.AtomicBoolean

/** Stable errors; descriptions never include private material or transfer passwords. */
class JacsVaultException(val code: Code, cause: Throwable? = null) :
    Exception(code.name, cause) {
    enum class Code {
        CANCELLED, BACKGROUNDED, CLOSED, BUSY, LOCKED, UNAVAILABLE, NOT_ENROLLED,
        LOCKOUT, PERMANENT_LOCKOUT, KEY_INVALIDATED, KEY_POLICY, MISSING_RECORD,
        ALREADY_EXISTS, INVALID_RECORD, INTEGRITY, STORAGE, CRYPTO
    }
}

/** Independent of Android so cancellation/order guarantees run in host tests. */
internal class JacsVaultState<S> {
    class Ticket internal constructor(val generation: Long) {
        val cancelled = AtomicBoolean(false)
        internal var cipher: Any? = null
        internal var authenticated = false
    }
    data class Invalidated<S>(val ticket: Ticket?, val session: S?)
    private var generation = 0L
    private var pending: Ticket? = null
    private var session: S? = null
    private var closed = false

    @Synchronized fun begin(needsSession: Boolean, opensSession: Boolean = false): Ticket {
        if (closed) throw JacsVaultException(JacsVaultException.Code.CLOSED)
        if (pending != null || (opensSession && session != null))
            throw JacsVaultException(JacsVaultException.Code.BUSY)
        if (needsSession && session == null) throw JacsVaultException(JacsVaultException.Code.LOCKED)
        return Ticket(++generation).also { pending = it }
    }
    @Synchronized fun current(ticket: Ticket): Boolean =
        !closed && pending === ticket && !ticket.cancelled.get()
    @Synchronized fun owns(ticket: Ticket): Boolean = pending === ticket
    @Synchronized fun cancel(ticket: Ticket): Boolean {
        if (pending !== ticket) return false
        return ticket.cancelled.compareAndSet(false, true)
    }
    @Synchronized fun bindCipher(ticket: Ticket, cipher: Any): Boolean {
        if (!current(ticket) || ticket.cipher != null) return false
        ticket.cipher = cipher
        return true
    }
    @Synchronized fun authenticate(ticket: Ticket, cipher: Any?): Boolean {
        if (!current(ticket) || ticket.authenticated || ticket.cipher == null || ticket.cipher !== cipher)
            return false
        ticket.authenticated = true
        return true
    }
    @Synchronized fun session(ticket: Ticket): S {
        if (!current(ticket)) throw JacsVaultException(JacsVaultException.Code.CANCELLED)
        return session ?: throw JacsVaultException(JacsVaultException.Code.LOCKED)
    }
    @Synchronized fun install(ticket: Ticket, value: S): Boolean {
        if (!current(ticket) || !ticket.authenticated || session != null) return false
        session = value
        return true
    }
    @Synchronized fun finish(ticket: Ticket): Boolean {
        if (!current(ticket)) return false
        pending = null
        ticket.cipher = null
        return true
    }
    @Synchronized fun isUnlocked(): Boolean = !closed && session != null && pending?.cancelled?.get() != true
    @Synchronized fun invalidate(permanently: Boolean = false): Invalidated<S> {
        generation++
        if (permanently) closed = true
        val result = Invalidated(pending, session)
        pending?.cancelled?.set(true)
        pending?.cipher = null
        pending = null
        session = null
        return result
    }
}
