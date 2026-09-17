import Foundation
import LocalAuthentication
import Security
import JacsMobile
#if canImport(UIKit)
import UIKit
#endif

internal protocol JacsBiometricAuthorizing: AnyObject {
    var context: LAContext? { get }
    var domainState: Data? { get }
    func authenticate(reason: String, completion: @escaping (Result<Void, JacsBiometricError>) -> Void)
    func invalidate()
}

internal final class SystemBiometricAuthorization: JacsBiometricAuthorizing {
    private let native = LAContext()
    var context: LAContext? { native }
    var domainState: Data? { native.evaluatedPolicyDomainState }

    init() {
        native.localizedFallbackTitle = ""
        native.touchIDAuthenticationAllowableReuseDuration = 0
    }

    func authenticate(reason: String, completion: @escaping (Result<Void, JacsBiometricError>) -> Void) {
        guard !reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            completion(.failure(.authenticationFailed)); return
        }
        var error: NSError?
        guard native.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            completion(.failure(Self.map(error))); return
        }
        native.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) {
            success, error in
            if success {
                // The same context carries the biometric credential to Keychain.
                // Retrieval must not cause a second prompt or passcode fallback.
                self.native.interactionNotAllowed = true
                completion(.success(()))
            } else {
                completion(.failure(Self.map(error)))
            }
        }
    }

    private static func map(_ error: Error?) -> JacsBiometricError {
        switch (error as? LAError)?.code {
        case .userCancel, .appCancel, .systemCancel, .userFallback: return .cancelled
        case .biometryLockout: return .biometricsLockedOut
        case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet:
            return .biometricsUnavailable
        default: return .authenticationFailed
        }
    }
    func invalidate() { native.invalidate() }
}

internal protocol JacsVaultRecordStore {
    func add(_ data: Data, account: String, authorization: JacsBiometricAuthorizing) throws
    func read(account: String, authorization: JacsBiometricAuthorizing) throws -> Data
    func delete(account: String) throws
}

/// A single atomic Keychain record contains the encrypted portable material and
/// its random wrapping secret. No two-store commit can leave a dangling key or
/// destroy the last recoverable copy. The namespace is distinct from the older
/// low-level password-only JacsKeychain API and never migrates weaker records.
internal final class SystemVaultRecordStore: JacsVaultRecordStore {
    let service: String
    init(service: String) { self.service = service + ".biometric-vault.v1" }

    private func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false,
         kSecUseDataProtectionKeychain as String: true]
    }

    func add(_ data: Data, account: String, authorization: JacsBiometricAuthorizing) throws {
        guard let context = authorization.context else { throw JacsBiometricError.authenticationFailed }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error
        ) else { throw JacsBiometricError.biometricsUnavailable }
        var item = query(account)
        item[kSecAttrAccessControl as String] = access
        item[kSecUseAuthenticationContext as String] = context
        item[kSecValueData as String] = data
        try check(SecItemAdd(item as CFDictionary, nil))
    }

    func read(account: String, authorization: JacsBiometricAuthorizing) throws -> Data {
        guard let context = authorization.context else { throw JacsBiometricError.authenticationFailed }
        var item = query(account)
        item[kSecReturnData as String] = true
        item[kSecReturnAttributes as String] = true
        item[kSecMatchLimit as String] = kSecMatchLimitOne
        item[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        try check(SecItemCopyMatching(item as CFDictionary, &result))
        guard let attributes = result as? [String: Any],
              attributes[kSecAttrService as String] as? String == service,
              attributes[kSecAttrAccount as String] as? String == account,
              attributes[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String,
              (attributes[kSecAttrSynchronizable as String] as? NSNumber)?.boolValue != true,
              let access = attributes[kSecAttrAccessControl as String] as CFTypeRef?,
              CFGetTypeID(access) == SecAccessControlGetTypeID(),
              let data = attributes[kSecValueData as String] as? Data else {
            throw JacsBiometricError.invalidStoredRecord
        }
        // Apple exposes no public getter for persisted ACL constraint flags.
        // We therefore create this dedicated namespace exclusively with the
        // fixed ACL above, require a fresh biometrics-only LA policy, and bind
        // the record to evaluatedPolicyDomainState in the vault below.
        return data
    }

    func delete(account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        if status != errSecItemNotFound { try check(status) }
    }

    private func check(_ status: OSStatus) throws {
        switch status {
        case errSecSuccess: return
        case errSecDuplicateItem: throw JacsBiometricError.alreadyExists
        case errSecItemNotFound: throw JacsBiometricError.notFoundOrEnrollmentChanged
        case errSecUserCanceled: throw JacsBiometricError.cancelled
        case errSecAuthFailed, errSecInteractionNotAllowed: throw JacsBiometricError.authenticationFailed
        default: throw JacsBiometricError.keychainStatus(status)
        }
    }
}

internal protocol JacsVaultAgentFactory {
    func create() throws -> JacsSessionAgent
    func restore(materialJSON: String, password: String) throws -> JacsSessionAgent
    func serialize(_ material: EncryptedAgentMaterial) throws -> String
}

internal struct RustVaultAgentFactory: JacsVaultAgentFactory {
    func create() throws -> JacsSessionAgent { RustSessionAgent(try MobileAgent.createDefault()) }
    func restore(materialJSON: String, password: String) throws -> JacsSessionAgent {
        let material = try materialFromJson(json: materialJSON)
        guard material.algorithm == .pq2025 else { throw JacsBiometricError.unsupportedAlgorithm }
        return RustSessionAgent(try MobileAgent.importEncryptedAgent(material: material, password: password))
    }
    func serialize(_ material: EncryptedAgentMaterial) throws -> String {
        guard material.algorithm == .pq2025 else { throw JacsBiometricError.unsupportedAlgorithm }
        return try materialToJson(material: material)
    }
}

/// Default PQ custody with biometric-only authorization and cancellable async
/// sessions. The wrapping secret and encrypted material are persisted atomically
/// in a device-only Keychain item. Never stores a plaintext signing private key.
///
/// A cancellation after the atomic save can leave a complete LOCKED record;
/// unlock the same account to recover it. Existing accounts are never replaced.
/// Enrollment changes / lost Keychain records require a separately protected
/// recovery export. This library never falls back to a passcode or server key.
public final class JacsBiometricVault {
    private static let maximumRecordBytes = 1024 * 1024
    private struct Record: Codable {
        let version: Int
        let account: String
        let biometricDomain: Data
        let wrappingPassword: String
        let materialJSON: String
    }
    private final class WeakSession {
        weak var value: JacsBiometricSession?
        init(_ value: JacsBiometricSession) { self.value = value }
    }
    private let lock = NSLock()
    private var active = true
    private var pending: [UUID: JacsBiometricOperation] = [:]
    private var sessions: [WeakSession] = []
    private let store: JacsVaultRecordStore
    private let factory: JacsVaultAgentFactory
    private let authorization: () -> JacsBiometricAuthorizing
    private let worker: DispatchQueue
    private let callbacks: DispatchQueue
    private var observers: [NSObjectProtocol] = []

    public convenience init(service: String, callbackQueue: DispatchQueue = .main) {
        self.init(store: SystemVaultRecordStore(service: service), factory: RustVaultAgentFactory(),
                  authorization: { SystemBiometricAuthorization() }, callbacks: callbackQueue)
        #if canImport(UIKit)
        for notification in [UIApplication.didEnterBackgroundNotification,
                             UIApplication.protectedDataWillBecomeUnavailableNotification] {
            observers.append(NotificationCenter.default.addObserver(forName: notification,
                object: nil, queue: nil) { [weak self] _ in self?.invalidate() })
        }
        #endif
    }

    internal init(store: JacsVaultRecordStore, factory: JacsVaultAgentFactory,
                  authorization: @escaping () -> JacsBiometricAuthorizing,
                  callbacks: DispatchQueue,
                  worker: DispatchQueue = DispatchQueue(label: "ai.hai.jacs.biometric-vault", qos: .userInitiated)) {
        self.store = store; self.factory = factory; self.authorization = authorization
        self.callbacks = callbacks; self.worker = worker
    }

    /// Call on logout; also invoked automatically on background/device lock.
    /// Invalidates the LAContext immediately. Pending results cannot resurrect
    /// sessions. This never deletes the durable encrypted identity.
    public func invalidate() {
        lock.lock()
        active = false
        let operations = Array(pending.values)
        let live = sessions.compactMap { $0.value }
        sessions = []
        lock.unlock()
        operations.forEach { $0.cancel() }
        live.forEach { $0.close() }
    }

    /// Re-enable requests when the caller is foreground and authorized again.
    /// Does not unlock anything or reuse any biometric credentials.
    public func resume() { lock.lock(); active = true; lock.unlock() }

    deinit {
        observers.forEach { NotificationCenter.default.removeObserver($0) }
        invalidate()
    }

    @discardableResult
    public func create(account: String, reason: String,
        completion: @escaping (Result<JacsBiometricSession, JacsBiometricError>) -> Void) -> JacsBiometricOperation {
        open(account: account, reason: reason, create: { try self.factory.create() }, completion: completion)
    }

    /// Consumes this handle: it is cleared on success, failure, or cancellation.
    /// On success the session owns a separately imported Rust handle. This also
    /// relocks other references to the supplied MobileAgent.
    @discardableResult
    public func protect(agent: MobileAgent, account: String, reason: String,
        completion: @escaping (Result<JacsBiometricSession, JacsBiometricError>) -> Void) -> JacsBiometricOperation {
        let source = RustSessionAgent(agent)
        return open(account: account, reason: reason, create: { source },
                    cleanup: { source.clear() }, completion: completion)
    }

    @discardableResult
    public func unlock(account: String, reason: String,
        completion: @escaping (Result<JacsBiometricSession, JacsBiometricError>) -> Void) -> JacsBiometricOperation {
        open(account: account, reason: reason, create: nil, completion: completion)
    }

    /// Receive a transferable PQ identity and immediately rewrap it for this
    /// device. Expected ID/key must come from an independently trusted source,
    /// never from the transfer ciphertext or QR payload itself.
    @discardableResult
    public func receive(material: EncryptedAgentMaterial, code: String,
                        expectedAgentID: String, expectedPublicKey: Data,
                        account: String, reason: String,
        completion: @escaping (Result<JacsBiometricSession, JacsBiometricError>) -> Void) -> JacsBiometricOperation {
        open(account: account, reason: reason, create: {
            guard material.algorithm == .pq2025 else { throw JacsBiometricError.unsupportedAlgorithm }
            return RustSessionAgent(try MobileAgent.importPinned(material: material, code: code,
                expectedAgentId: expectedAgentID, expectedPublicKey: expectedPublicKey,
                expectedAlgorithm: .pq2025))
        }, completion: completion)
    }

    private func open(account: String, reason: String, create: (() throws -> JacsSessionAgent)?,
                      cleanup: @escaping () -> Void = {},
                      completion: @escaping (Result<JacsBiometricSession, JacsBiometricError>) -> Void) -> JacsBiometricOperation {
        let id = UUID()
        let auth = authorization()
        let operation = JacsBiometricOperation { [weak self, callbacks, worker] in
            auth.invalidate()
            worker.async(execute: cleanup)
            callbacks.async {
                self?.remove(id)
                completion(.failure(.cancelled))
            }
        }
        lock.lock()
        let rejection: JacsBiometricError? = !active ? .inactive :
            (pending.values.contains { $0.isPending } ? .busy : nil)
        if rejection == nil { pending[id] = operation }
        lock.unlock()
        if let rejection = rejection {
            auth.invalidate()
            worker.async(execute: cleanup)
            finish(operation, id: id, result: .failure(rejection), completion: completion)
            return operation
        }
        guard !account.isEmpty && account.utf8.count <= 128 else {
            auth.invalidate()
            worker.async(execute: cleanup)
            finish(operation, id: id, result: .failure(.invalidStoredRecord), completion: completion)
            return operation
        }
        auth.authenticate(reason: reason) { [self] authorizationResult in
            worker.async {
                defer { auth.invalidate(); cleanup() }
                guard operation.claimWork() else { return }
                let result: Result<JacsBiometricSession, JacsBiometricError>
                do {
                    try authorizationResult.get()
                    guard let domain = auth.domainState, !domain.isEmpty else {
                        throw JacsBiometricError.biometricsUnavailable
                    }
                    let agent: JacsSessionAgent
                    if let create = create {
                        let source = try create()
                        defer { source.clear() }
                        var random = Data(count: 32)
                        defer { random.resetBytes(in: 0..<random.count) }
                        let status = random.withUnsafeMutableBytes {
                            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
                        }
                        guard status == errSecSuccess else { throw JacsBiometricError.keychainStatus(status) }
                        let password = random.base64EncodedString()
                        let materialJSON = try factory.serialize(source.export(password))
                        var encoded = try JSONEncoder().encode(Record(version: 1, account: account,
                            biometricDomain: domain, wrappingPassword: password, materialJSON: materialJSON))
                        defer { encoded.resetBytes(in: 0..<encoded.count) }
                        guard encoded.count <= Self.maximumRecordBytes else {
                            throw JacsBiometricError.invalidStoredRecord
                        }
                        guard operation.isPending else { return }
                        try store.add(encoded, account: account, authorization: auth)
                        // Import from the exact encrypted bytes just committed;
                        // the caller's original handle is always relocked.
                        agent = try factory.restore(materialJSON: materialJSON, password: password)
                    } else {
                        var encoded = try store.read(account: account, authorization: auth)
                        defer { encoded.resetBytes(in: 0..<encoded.count) }
                        guard encoded.count <= Self.maximumRecordBytes,
                              let record = try? JSONDecoder().decode(Record.self, from: encoded),
                              record.version == 1, record.account == account,
                              Data(base64Encoded: record.wrappingPassword)?.count == 32 else {
                            throw JacsBiometricError.invalidStoredRecord
                        }
                        guard record.biometricDomain == domain else {
                            throw JacsBiometricError.notFoundOrEnrollmentChanged
                        }
                        agent = try factory.restore(materialJSON: record.materialJSON, password: record.wrappingPassword)
                    }
                    let session = JacsBiometricSession(agent: agent, worker: worker, callbacks: callbacks)
                    lock.lock()
                    let canDeliver = active && operation.isPending
                    if canDeliver {
                        sessions.removeAll { $0.value == nil }
                        sessions.append(WeakSession(session))
                    }
                    lock.unlock()
                    if !canDeliver { session.close() }
                    result = canDeliver ? .success(session) : .failure(.cancelled)
                } catch let error as JacsBiometricError { result = .failure(error) }
                catch { result = .failure(.cryptographyFailed) }
                finish(operation, id: id, result: result, completion: completion)
            }
        }
        return operation
    }

    private func remove(_ id: UUID) { lock.lock(); pending.removeValue(forKey: id); lock.unlock() }

    private func finish(_ operation: JacsBiometricOperation, id: UUID,
                        result: Result<JacsBiometricSession, JacsBiometricError>,
                        completion: @escaping (Result<JacsBiometricSession, JacsBiometricError>) -> Void) {
        callbacks.async { [weak self] in
            self?.remove(id)
            guard operation.claimCompletion() else {
                if case .success(let session) = result { session.close() }
                return
            }
            if case .success(let session) = result, !session.isActive {
                completion(.failure(.cancelled))
                return
            }
            completion(result)
        }
    }
}
