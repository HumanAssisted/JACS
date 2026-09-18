import Foundation
import JacsMobile

/// Stable lifecycle errors. Underlying biometric/keychain errors never include
/// passwords, encrypted records, or signing inputs in their descriptions.
public enum JacsBiometricError: Error, Equatable {
    case cancelled
    case inactive
    case busy
    case biometricsUnavailable
    case biometricsLockedOut
    case authenticationFailed
    case alreadyExists
    case notFoundOrEnrollmentChanged
    case invalidStoredRecord
    case unsupportedAlgorithm
    case keychainStatus(Int32)
    case cryptographyFailed
}

/// Display the code directly to the receiver; send only encrypted material to
/// the relay. Neither field should be logged or included in diagnostics.
public struct JacsBiometricTransfer {
    public let code: String
    public let material: EncryptedAgentMaterial
}

/// Cancels a pending operation, including a result awaiting callback delivery.
/// Cancelling after completion does not close a returned session; use close().
public final class JacsBiometricOperation {
    private let lock = NSLock()
    private var completed = false
    private var cancelled = false
    private var workStarted = false
    private var cancellation: (() -> Void)?

    internal init(cancellation: @escaping () -> Void) { self.cancellation = cancellation }

    public func cancel() {
        lock.lock()
        guard !completed else { lock.unlock(); return }
        completed = true
        cancelled = true
        let action = cancellation
        cancellation = nil
        lock.unlock()
        action?()
    }

    internal var isPending: Bool {
        lock.lock(); defer { lock.unlock() }
        return !completed
    }

    internal func claimCompletion() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !completed && !cancelled else { return false }
        completed = true
        cancellation = nil
        return true
    }

    internal func claimWork() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !completed && !workStarted else { return false }
        workStarted = true
        return true
    }
}

internal protocol JacsSessionAgent: AnyObject {
    func sign(_ json: String) throws -> String
    func export(_ password: String) throws -> EncryptedAgentMaterial
    func requestAuth(method: String, url: String, body: Data, audience: String) throws -> String
    func identity() throws -> String
    func clear()
}

internal final class RustSessionAgent: JacsSessionAgent {
    let agent: MobileAgent
    init(_ agent: MobileAgent) { self.agent = agent }
    func sign(_ json: String) throws -> String { try agent.signMessageJson(json: json) }
    func export(_ password: String) throws -> EncryptedAgentMaterial {
        try agent.exportEncryptedAgent(password: password)
    }
    func requestAuth(method: String, url: String, body: Data, audience: String) throws -> String {
        try agent.buildRequestAuthHeader(method: method, url: url, body: body, audience: audience)
    }
    func identity() throws -> String { try agent.exportAgentJson() }
    func clear() { try? agent.clearSecrets() }
    deinit { clear() }
}

/// Owns one unlocked Rust agent without exposing an escapable raw handle.
/// All crypto runs on the vault worker. close() immediately rejects new work
/// and queued results, then clears Rust secrets after an in-flight call ends.
public final class JacsBiometricSession {
    private let lock = NSLock()
    private var active = true
    private var pendingTransfer: UUID?
    private let agent: JacsSessionAgent
    private let worker: DispatchQueue
    private let callbacks: DispatchQueue

    internal init(agent: JacsSessionAgent, worker: DispatchQueue, callbacks: DispatchQueue) {
        self.agent = agent
        self.worker = worker
        self.callbacks = callbacks
    }

    public var isActive: Bool {
        lock.lock(); defer { lock.unlock() }
        return active
    }

    public func close() {
        lock.lock()
        let wasActive = active
        active = false
        pendingTransfer = nil
        lock.unlock()
        if wasActive { worker.async { [agent] in agent.clear() } }
    }

    deinit { close() }

    private func perform<T>(_ operation: @escaping (JacsSessionAgent) throws -> T,
                            completion: @escaping (Result<T, JacsBiometricError>) -> Void) {
        worker.async { [self] in
            let result: Result<T, JacsBiometricError>
            if !isActive {
                result = .failure(.inactive)
            } else {
                do { result = .success(try operation(agent)) }
                catch { result = .failure(.cryptographyFailed) }
            }
            callbacks.async { [self] in
                // A background/logout event can occur after Rust returns and
                // before this queued callback gets the main thread.
                completion(isActive ? result : .failure(.inactive))
            }
        }
    }

    public func signMessageJSON(_ json: String,
                                completion: @escaping (Result<String, JacsBiometricError>) -> Void) {
        perform({ try $0.sign(json) }, completion: completion)
    }

    /// Use a freshly generated transfer code. The OS wrapping secret never leaves
    /// the vault; this exports only a Rust-encrypted transferable envelope.
    public func exportEncryptedMaterial(password: String,
        completion: @escaping (Result<EncryptedAgentMaterial, JacsBiometricError>) -> Void) {
        perform({ try $0.export(password) }, completion: completion)
    }

    /// Generate the six-word code in Rust and clear this session before result
    /// delivery. Background/logout/cancellation still suppress queued results.
    public func createTransfer(
        completion: @escaping (Result<JacsBiometricTransfer, JacsBiometricError>) -> Void) {
        worker.async { [self] in
            let result: Result<JacsBiometricTransfer, JacsBiometricError>
            if !isActive {
                result = .failure(.inactive)
            } else {
                do {
                    let code = try generateTransferCode()
                    result = .success(JacsBiometricTransfer(code: code, material: try agent.export(code)))
                } catch { result = .failure(.cryptographyFailed) }
            }
            let delivery = UUID()
            lock.lock()
            let allowed = active
            active = false
            pendingTransfer = allowed ? delivery : nil
            lock.unlock()
            agent.clear()
            callbacks.async { [self] in
                lock.lock()
                let deliver = pendingTransfer == delivery
                if deliver { pendingTransfer = nil }
                lock.unlock()
                completion(deliver ? result : .failure(.inactive))
            }
        }
    }

    public func buildRequestAuthHeader(method: String, url: String, body: Data, audience: String,
        completion: @escaping (Result<String, JacsBiometricError>) -> Void) {
        perform({ try $0.requestAuth(method: method, url: url, body: body, audience: audience) },
                completion: completion)
    }

    public func exportIdentityJSON(
        completion: @escaping (Result<String, JacsBiometricError>) -> Void) {
        perform({ try $0.identity() }, completion: completion)
    }
}
