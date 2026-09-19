import XCTest
import LocalAuthentication
import Security
import JacsMobile
@testable import JacsMobilePlatform

private final class FakeAuthorization: JacsBiometricAuthorizing {
    var context: LAContext? { nil }
    var domainState: Data? = Data([1, 2, 3])
    var callback: ((Result<Void, JacsBiometricError>) -> Void)?
    var invalidations = 0
    func authenticate(reason: String, completion: @escaping (Result<Void, JacsBiometricError>) -> Void) {
        callback = completion
    }
    func invalidate() { invalidations += 1 }
    func succeed() { callback?(.success(())) }
}

private final class FakeStore: JacsVaultRecordStore {
    var records: [String: Data] = [:]
    var addError: JacsBiometricError?
    var reads = 0
    func add(_ data: Data, account: String, authorization: JacsBiometricAuthorizing) throws {
        if let error = addError { throw error }
        guard records[account] == nil else { throw JacsBiometricError.alreadyExists }
        records[account] = data
    }
    func read(account: String, authorization: JacsBiometricAuthorizing) throws -> Data {
        reads += 1
        guard let data = records[account] else { throw JacsBiometricError.notFoundOrEnrollmentChanged }
        return data
    }
    func delete(account: String) throws { records.removeValue(forKey: account) }
    var replaceError: JacsBiometricError?
    func replace(_ data: Data, account: String, authorization: JacsBiometricAuthorizing) throws {
        if let error = replaceError { throw error }
        guard records[account] != nil else { throw JacsBiometricError.notFoundOrEnrollmentChanged }
        records[account] = data
    }
    func inspect(account: String) -> JacsBiometricInspection {
        JacsBiometricInspection(state: records[account] == nil ? .absent : .presentLocked, identity: nil)
    }

}

private final class FakeAgent: JacsSessionAgent {
    var cleared = false
    var signCalls = 0
    var signHook: (() -> Void)?
    func sign(_ json: String) throws -> String {
        signCalls += 1
        signHook?()
        XCTAssertFalse(cleared)
        return "signed:" + json
    }
    func signDocument(_ json: String) throws -> String { try sign(json) }
    func signPreparedDocument(_ preparedJson: String) throws -> String { try sign(preparedJson) }
    func recovery() throws -> MobileRecoveryExport {
        return MobileRecoveryExport(code: "0123-4567-89AB-CDEF-0123-4567-89AB-CDEF",
            material: try export("one two three four five six"))
    }
    func export(_ password: String) throws -> EncryptedAgentMaterial {
        XCTAssertTrue(Data(base64Encoded: password)?.count == 32 || password.split(separator: " ").count == 6)
        return EncryptedAgentMaterial(configJson: "{}", agentJson: "{}", publicKey: Data([1]),
            encryptedPrivateKey: Data([2]), algorithm: .pq2025)
    }
    func requestAuth(method: String, url: String, body: Data, audience: String) throws -> String { "auth" }
    func identity() throws -> String { "public-identity" }
    func clear() { cleared = true }
}

private final class FakeFactory: JacsVaultAgentFactory {
    var created: [FakeAgent] = []
    var restored: [FakeAgent] = []
    var serializedMaterial = "encrypted-pq-material"
    func create() throws -> JacsSessionAgent {
        let agent = FakeAgent(); created.append(agent); return agent
    }
    func createHuman() throws -> JacsSessionAgent { try create() }
    func restore(materialJSON: String, password: String) throws -> JacsSessionAgent {
        XCTAssertEqual(materialJSON, "encrypted-pq-material")
        XCTAssertEqual(Data(base64Encoded: password)?.count, 32)
        let agent = FakeAgent(); restored.append(agent); return agent
    }
    func serialize(_ material: EncryptedAgentMaterial) throws -> String { serializedMaterial }
}

final class JacsBiometricVaultTests: XCTestCase {
    private var store: FakeStore!
    private var factory: FakeFactory!
    private var auth: FakeAuthorization!
    private var worker: DispatchQueue!
    private var callbacks: DispatchQueue!
    private var vault: JacsBiometricVault!

    override func setUp() {
        store = FakeStore(); factory = FakeFactory(); auth = FakeAuthorization()
        worker = DispatchQueue(label: "test-vault-worker")
        callbacks = DispatchQueue(label: "test-vault-callbacks")
        vault = JacsBiometricVault(store: store, factory: factory,
            authorization: { [unowned self] in self.auth }, callbacks: callbacks, worker: worker)
    }
    override func tearDown() {
        vault.invalidate()
        worker.sync {}
        callbacks.sync {}
        vault = nil
    }

    private func createSession() -> JacsBiometricSession {
        let done = expectation(description: "create")
        var session: JacsBiometricSession?
        vault.create(account: "agent", reason: "Unlock identity") {
            if case .success(let value) = $0 { session = value } else { XCTFail("create failed") }
            done.fulfill()
        }
        auth.succeed()
        wait(for: [done], timeout: 5)
        return session!
    }

    private func authenticated<T>(_ start: (@escaping (Result<T, JacsBiometricError>) -> Void) -> JacsBiometricOperation) throws -> T {
        auth = FakeAuthorization()
        let done = expectation(description: "authenticated vault operation")
        var outcome: Result<T, JacsBiometricError>?
        _ = start { outcome = $0; done.fulfill() }
        auth.succeed()
        wait(for: [done], timeout: 20)
        return try XCTUnwrap(outcome).get()
    }

    func testOwnedRotationPersistsCandidateAndReconcilesExactCommit() throws {
        vault = JacsBiometricVault(store: store, factory: RustVaultAgentFactory(),
            authorization: { [unowned self] in self.auth }, callbacks: callbacks, worker: worker)
        let session: JacsBiometricSession = try authenticated { vault.createHuman(account: "agent", reason: "Create", completion: $0) }
        let described = expectation(description: "owned public metadata")
        var old: MobilePublicIdentity?
        session.describe { old = try? $0.get(); described.fulfill() }
        wait(for: [described], timeout: 10)
        let original = try XCTUnwrap(old)
        let originalRecord = store.records["agent"]
        store.replaceError = .keychainStatus(-1)
        XCTAssertThrowsError(try authenticated { vault.prepareKeyRotation(account: "agent", reason: "Rotate", completion: $0) } as MobilePublicIdentity)
        XCTAssertEqual(store.records["agent"], originalRecord)
        store.replaceError = nil
        let stage: MobilePublicIdentity = try authenticated { vault.prepareKeyRotation(account: "agent", reason: "Rotate", completion: $0) }
        XCTAssertNotEqual(stage.publicKeyBase64, original.publicKeyBase64)
        let candidate = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(stage.agentJson.utf8)) as? [String: Any])
        let version = try XCTUnwrap(candidate["jacsVersion"] as? String)
        let again: MobilePublicIdentity = try authenticated { vault.prepareKeyRotation(account: "agent", reason: "Resume", completion: $0) }
        XCTAssertEqual(again.agentJson, stage.agentJson)
        let stagedRecord = store.records["agent"]
        // Reconstruct the vault: no candidate handle or plaintext code survives.
        vault.invalidate(); worker.sync {}
        vault = JacsBiometricVault(store: store, factory: RustVaultAgentFactory(),
            authorization: { [unowned self] in self.auth }, callbacks: callbacks, worker: worker)
        let resumed: MobilePublicIdentity? = try authenticated { vault.keyRotationStatus(account: "agent", reason: "Resume", completion: $0) }
        XCTAssertEqual(resumed?.agentJson, stage.agentJson)
        let proof: String = try authenticated { vault.signRotationDocumentJSON(account: "agent", reason: "Prove", candidateVersion: version,
            json: "{\"purpose\":\"candidate possession\"}", completion: $0) }
        let key = try XCTUnwrap(Data(base64Encoded: stage.publicKeyBase64))
        XCTAssertTrue(try verifyWithKey(json: proof, publicKey: key, algorithm: .pq2025).valid)
        let recovery: JacsBiometricRecovery = try authenticated { vault.createRotationRecovery(account: "agent", reason: "Save", candidateVersion: version, completion: $0) }
        XCTAssertEqual(try JacsMobile.verifyRecovery(material: recovery.material, code: recovery.code,
            expectedAgentId: candidate["jacsId"] as! String, expectedPublicKey: key, expectedAlgorithm: .pq2025), stage.agentJson)
        XCTAssertThrowsError(try authenticated { vault.commitKeyRotation(account: "agent", reason: "Wrong acceptance",
            acceptedIdentityJSON: original.agentJson, acceptedPublicKey: Data(base64Encoded: original.publicKeyBase64)!, completion: $0) } as String)
        XCTAssertEqual(store.records["agent"], stagedRecord)
        // A failed atomic local write after server acceptance retains BOTH records.
        store.replaceError = .keychainStatus(-1)
        XCTAssertThrowsError(try authenticated { vault.commitKeyRotation(account: "agent", reason: "Commit",
            acceptedIdentityJSON: stage.agentJson, acceptedPublicKey: key, completion: $0) } as String)
        XCTAssertEqual(store.records["agent"], stagedRecord)
        store.replaceError = nil
        for _ in 0..<2 {
            let committed: String = try authenticated { vault.commitKeyRotation(account: "agent", reason: "Reconcile",
                acceptedIdentityJSON: stage.agentJson, acceptedPublicKey: key, completion: $0) }
            XCTAssertEqual(committed, stage.agentJson)
        }
        let pending: MobilePublicIdentity? = try authenticated { vault.keyRotationStatus(account: "agent", reason: "Status", completion: $0) }
        XCTAssertNil(pending)
    }

    func testInspectDistinguishesUnreadableRecordsFromKeychainFailuresWithoutPrompting() {
        let outcomes: [(OSStatus, JacsBiometricRecordState?)] = [
            (errSecSuccess, .presentLocked), (errSecInteractionNotAllowed, .presentLocked),
            (errSecItemNotFound, .absent), (errSecDecode, .unreadable),
            (errSecMissingEntitlement, nil), (errSecNotAvailable, nil), (errSecParam, nil)
        ]
        for (status, expectedState) in outcomes {
            let systemStore = SystemVaultRecordStore(service: "test-inspection") { query in
                let request = query as! [String: Any]
                XCTAssertEqual(request[kSecUseAuthenticationUI as String] as? String, kSecUseAuthenticationUIFail as String)
                XCTAssertEqual(request[kSecReturnAttributes as String] as? Bool, true)
                XCTAssertNil(request[kSecReturnData as String])
                return status
            }
            vault = JacsBiometricVault(store: systemStore, factory: factory,
                authorization: { [unowned self] in self.auth }, callbacks: callbacks, worker: worker)
            let inspected = expectation(description: "nonprompting inspect status \(status)")
            vault.inspect(account: "agent") { result in
                switch result {
                case .success(let inspection):
                    XCTAssertNotNil(expectedState)
                    XCTAssertEqual(inspection.state, expectedState)
                    XCTAssertNil(inspection.identity)
                case .failure(.keychainStatus(let received)):
                    XCTAssertNil(expectedState)
                    XCTAssertEqual(received, status)
                case .failure(let error): XCTFail("unexpected inspection error: \(error)")
                }
                inspected.fulfill()
            }
            wait(for: [inspected], timeout: 5)
            XCTAssertNil(auth.callback)
        }
    }

    func testRotationCancellationAndInspectNeverCreateOrLoseAStage() throws {
        vault = JacsBiometricVault(store: store, factory: RustVaultAgentFactory(),
            authorization: { [unowned self] in self.auth }, callbacks: callbacks, worker: worker)
        let session: JacsBiometricSession = try authenticated { vault.createHuman(account: "agent", reason: "Create", completion: $0) }
        session.close()
        let record = store.records["agent"]
        auth = FakeAuthorization()
        let cancelled = expectation(description: "cancel before biometric")
        let request = vault.prepareKeyRotation(account: "agent", reason: "Rotate") {
            if case .failure(.cancelled) = $0 {} else { XCTFail("late stage escaped") }
            cancelled.fulfill()
        }
        request.cancel(); auth.succeed()
        wait(for: [cancelled], timeout: 10); worker.sync {}
        XCTAssertEqual(store.records["agent"], record)
        auth = FakeAuthorization()
        let inspected = expectation(description: "nonprompting inspect")
        vault.inspect(account: "agent") {
            XCTAssertEqual(try? $0.get().state, .presentLocked)
            XCTAssertNil(try? $0.get().identity)
            inspected.fulfill()
        }
        wait(for: [inspected], timeout: 10)
        XCTAssertNil(auth.callback)
        let stage: MobilePublicIdentity = try authenticated { vault.prepareKeyRotation(account: "agent", reason: "Rotate", completion: $0) }
        let identity = try JSONSerialization.jsonObject(with: Data(stage.agentJson.utf8)) as! [String: Any]
        XCTAssertThrowsError(try authenticated { vault.discardKeyRotation(account: "agent", reason: "Discard", candidateVersion: "wrong-version", completion: $0) } as Void)
        let _: Void = try authenticated { vault.discardKeyRotation(account: "agent", reason: "Discard", candidateVersion: identity["jacsVersion"] as! String, completion: $0) }
        let pending: MobilePublicIdentity? = try authenticated { vault.keyRotationStatus(account: "agent", reason: "Status", completion: $0) }
        XCTAssertNil(pending)
        // Background after the durable write but before callback delivery must
        // suppress the result while retaining the exact stage for reconciliation.
        auth = FakeAuthorization()
        callbacks.suspend()
        let late = expectation(description: "persisted stage late result suppressed")
        vault.prepareKeyRotation(account: "agent", reason: "Rotate") {
            if case .failure(.cancelled) = $0 {} else { XCTFail("late stage escaped") }
            late.fulfill()
        }
        auth.succeed(); worker.sync {}
        let persisted = store.records["agent"]
        vault.invalidate(); callbacks.resume()
        wait(for: [late], timeout: 10)
        XCTAssertEqual(store.records["agent"], persisted)
        vault.resume()
        let recovered: MobilePublicIdentity? = try authenticated { vault.keyRotationStatus(account: "agent", reason: "Reconcile", completion: $0) }
        XCTAssertNotNil(recovered)
    }

    func testCancellationRejectsLateAndRepeatedBiometricCallbacks() {
        let done = expectation(description: "cancelled once")
        done.assertForOverFulfill = true
        let operation = vault.create(account: "agent", reason: "Unlock identity") {
            if case .failure(.cancelled) = $0 {} else { XCTFail("expected cancellation") }
            done.fulfill()
        }
        operation.cancel()
        auth.succeed()
        auth.succeed()
        wait(for: [done], timeout: 5)
        worker.sync {}; callbacks.sync {}
        XCTAssertTrue(factory.created.isEmpty)
        XCTAssertTrue(store.records.isEmpty)
        XCTAssertGreaterThan(auth.invalidations, 0)
    }

    func testCancelledProtectClearsTheSuppliedRustHandle() throws {
        let agent = try MobileAgent.createDefault()
        let done = expectation(description: "protect cancelled")
        let operation = vault.protect(agent: agent, account: "agent", reason: "Protect") {
            if case .failure(.cancelled) = $0 {} else { XCTFail("expected cancelled protect") }
            done.fulfill()
        }
        operation.cancel()
        auth.succeed()
        wait(for: [done], timeout: 5)
        worker.sync {}
        XCTAssertFalse(try agent.isUnlocked())
        XCTAssertTrue(store.records.isEmpty)
    }

    func testLogoutBeforeQueuedDeliveryCannotResurrectSessionAndCanRecoverAtomicRecord() {
        callbacks.suspend()
        let done = expectation(description: "late result rejected")
        vault.create(account: "agent", reason: "Unlock identity") {
            if case .failure(.cancelled) = $0 {} else { XCTFail("late success escaped logout") }
            done.fulfill()
        }
        auth.succeed()
        worker.sync {}
        XCTAssertNotNil(store.records["agent"])
        vault.invalidate()
        callbacks.resume()
        wait(for: [done], timeout: 5)
        worker.sync {}; callbacks.sync {}
        XCTAssertTrue(factory.created.allSatisfy { $0.cleared })
        XCTAssertTrue(factory.restored.allSatisfy { $0.cleared })

        // The atomic record survives cancellation complete and locked.
        vault.resume()
        auth = FakeAuthorization()
        let recovered = expectation(description: "recover locked record")
        vault.unlock(account: "agent", reason: "Recover saved identity") {
            if case .success(let session) = $0 { session.close() } else { XCTFail("recovery failed") }
            recovered.fulfill()
        }
        auth.succeed()
        wait(for: [recovered], timeout: 5)
    }

    func testBackgroundInvalidatesActiveSessionAndQueuedSigningResult() {
        let session = createSession()
        callbacks.suspend()
        let done = expectation(description: "sign result invalidated")
        session.signMessageJSON("message") {
            if case .failure(.inactive) = $0 {} else { XCTFail("late signing result escaped") }
            done.fulfill()
        }
        worker.sync {}
        vault.invalidate()
        XCTAssertFalse(session.isActive)
        callbacks.resume()
        wait(for: [done], timeout: 5)
        worker.sync {}
        XCTAssertTrue(factory.restored[0].cleared)

        let denied = expectation(description: "new requests denied until resume")
        vault.unlock(account: "agent", reason: "Unlock") {
            if case .failure(.inactive) = $0 {} else { XCTFail("inactive vault accepted work") }
            denied.fulfill()
        }
        wait(for: [denied], timeout: 5)
    }

    func testPersistenceFailureClearsGeneratedKeyAndDoesNotReplaceExistingRecord() {
        store.records["agent"] = Data("existing-recovery-copy".utf8)
        let done = expectation(description: "duplicate rejected")
        vault.create(account: "agent", reason: "Unlock") {
            if case .failure(.alreadyExists) = $0 {} else { XCTFail("duplicate replaced") }
            done.fulfill()
        }
        auth.succeed()
        wait(for: [done], timeout: 5)
        worker.sync {}
        XCTAssertEqual(store.records["agent"], Data("existing-recovery-copy".utf8))
        XCTAssertTrue(factory.created[0].cleared)
        XCTAssertTrue(factory.restored.isEmpty)

        auth = FakeAuthorization()
        store.addError = .keychainStatus(-36)
        let failed = expectation(description: "save failure")
        vault.create(account: "another", reason: "Unlock") {
            if case .failure(.keychainStatus(-36)) = $0 {} else { XCTFail("wrong save failure") }
            failed.fulfill()
        }
        auth.succeed()
        wait(for: [failed], timeout: 5)
        worker.sync {}
        XCTAssertNil(store.records["another"])
        XCTAssertTrue(factory.created.allSatisfy { $0.cleared })
    }

    func testOversizedRecordIsRejectedBeforePersistenceAndClearsSource() {
        factory.serializedMaterial = String(repeating: "x", count: 1024 * 1024)
        let done = expectation(description: "oversized record rejected")
        vault.create(account: "agent", reason: "Unlock") {
            if case .failure(.invalidStoredRecord) = $0 {} else { XCTFail("oversized record persisted") }
            done.fulfill()
        }
        auth.succeed()
        wait(for: [done], timeout: 5)
        worker.sync {}
        XCTAssertTrue(store.records.isEmpty)
        XCTAssertTrue(factory.created[0].cleared)
        XCTAssertTrue(factory.restored.isEmpty)
    }

    func testInvalidationDoesNotWaitForInFlightCryptoAndSuppressesItsResult() {
        let session = createSession()
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        factory.restored[0].signHook = { entered.signal(); release.wait() }
        let done = expectation(description: "in-flight result invalidated")
        session.signMessageJSON("message") {
            if case .failure(.inactive) = $0 {} else { XCTFail("in-flight result escaped") }
            done.fulfill()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
        // This must return while the fake crypto is still blocked.
        vault.invalidate()
        XCTAssertFalse(session.isActive)
        release.signal()
        wait(for: [done], timeout: 5)
        worker.sync {}
        XCTAssertTrue(factory.restored[0].cleared)
    }

    func testOwnedHumanRecoveryWithRealRustPreservesWorkingRecordOnFailures() throws {
        let realVault = JacsBiometricVault(store: store, factory: RustVaultAgentFactory(),
            authorization: { [unowned self] in self.auth }, callbacks: callbacks, worker: worker)
        defer { realVault.invalidate(); worker.sync {} }
        var source: JacsBiometricSession?
        let created = expectation(description: "human created in owned vault")
        realVault.createHuman(account: "source", reason: "Set up") {
            if case .success(let value) = $0 { source = value } else { XCTFail("human creation failed") }
            created.fulfill()
        }
        auth.succeed()
        wait(for: [created], timeout: 15)
        var recovery: JacsBiometricRecovery?
        let exported = expectation(description: "generated recovery")
        source!.createRecovery {
            if case .success(let value) = $0 { recovery = value } else { XCTFail("recovery export failed") }
            exported.fulfill()
        }
        wait(for: [exported], timeout: 15)
        let backup = try XCTUnwrap(recovery)
        let identity = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(backup.material.agentJson.utf8)) as? [String: Any])
        XCTAssertEqual(identity["jacsAgentType"] as? String, "human")
        let id = try XCTUnwrap(identity["jacsId"] as? String)
        let original = store.records["source"]
        auth = FakeAuthorization()
        let verified = expectation(description: "noninteractive readback")
        realVault.verifyRecovery(material: backup.material, code: backup.code,
            expectedAgentID: id, expectedPublicKey: backup.material.publicKey) {
            if case .success(let identityJSON) = $0 { XCTAssertEqual(identityJSON, backup.material.agentJson) }
            else { XCTFail("readback failed") }
            verified.fulfill()
        }
        wait(for: [verified], timeout: 15)
        XCTAssertNil(auth.callback)
        XCTAssertEqual(store.records["source"], original)
        var malformed = backup.material
        malformed.encryptedPrivateKey = Data([0])
        for (account, material, code, expectedID) in [
            ("wrong-code", backup.material, "0000-0000-0000-0000-0000-0000-0000-0000", id),
            ("wrong-id", backup.material, backup.code, "wrong"),
            ("malformed", malformed, backup.code, id),
            ("source", backup.material, backup.code, id)
        ] {
            auth = FakeAuthorization()
            let refused = expectation(description: "recovery refused")
            realVault.receiveRecovery(material: material, code: code,
                expectedAgentID: expectedID, expectedPublicKey: backup.material.publicKey,
                account: account, reason: "Restore") {
                if case .failure = $0 {} else { XCTFail("invalid recovery replaced record") }
                refused.fulfill()
            }
            auth.succeed()
            wait(for: [refused], timeout: 15)
            XCTAssertEqual(store.records["source"], original)
            XCTAssertEqual(store.records.count, 1)
        }
        let removed = expectation(description: "explicit removal after candidate verification")
        realVault.delete(account: "source") {
            if case .success = $0 {} else { XCTFail("explicit delete failed") }
            removed.fulfill()
        }
        wait(for: [removed], timeout: 5)
        XCTAssertNil(store.records["source"])
        auth = FakeAuthorization()
        let restored = expectation(description: "same identity restored")
        realVault.receiveRecovery(material: backup.material, code: backup.code.lowercased(),
            expectedAgentID: id, expectedPublicKey: backup.material.publicKey,
            account: "source", reason: "Restore") { result in
            guard case .success(let session) = result else { XCTFail("restore failed"); restored.fulfill(); return }
            session.exportIdentityJSON {
                if case .success(let json) = $0 { XCTAssertEqual(json, backup.material.agentJson) }
                else { XCTFail("restored identity unavailable") }
                session.signDocumentJSON("{\"exact\":\"native terms\"}") { result in
                    if case .success(let signed) = result {
                        let verified = try? JacsMobile.verifyWithKey(json: signed, publicKey: backup.material.publicKey, algorithm: .pq2025)
                        XCTAssertEqual(verified?.valid, true)
                        let parsed = (try? JSONSerialization.jsonObject(with: Data(signed.utf8))) as? [String: Any]
                        XCTAssertNotNil(parsed?["jacsId"])
                        XCTAssertNotNil(parsed?["jacsVersion"])
                        XCTAssertNotNil(parsed?["jacsSha256"])
                    } else { XCTFail("owned full-document signing failed") }
                    session.close()
                    restored.fulfill()
                }
            }
        }
        auth.succeed()
        wait(for: [restored], timeout: 15)
        XCTAssertNotNil(store.records["source"])
    }

    func testExplicitDeleteIsScopedAndCancellationBeforeMutationKeepsRecord() {
        let session = createSession()
        store.records["other"] = Data([9])
        let original = store.records["agent"]
        worker.suspend()
        let cancelled = expectation(description: "delete cancelled")
        let request = vault.delete(account: "agent") {
            if case .failure(.cancelled) = $0 {} else { XCTFail("delete must cancel") }
            cancelled.fulfill()
        }
        request.cancel()
        worker.resume()
        wait(for: [cancelled], timeout: 5)
        worker.sync {}; callbacks.sync {}
        XCTAssertEqual(store.records["agent"], original)
        XCTAssertTrue(session.isActive)
        let deleted = expectation(description: "deliberate delete")
        vault.delete(account: "agent") {
            if case .success = $0 {} else { XCTFail("delete failed") }
            deleted.fulfill()
        }
        wait(for: [deleted], timeout: 5)
        XCTAssertNil(store.records["agent"])
        XCTAssertEqual(store.records["other"], Data([9]))
        XCTAssertFalse(session.isActive)
        vault.invalidate()
        let refused = expectation(description: "inactive delete refused")
        vault.delete(account: "other") {
            if case .failure(.inactive) = $0 {} else { XCTFail("inactive delete allowed") }
            refused.fulfill()
        }
        wait(for: [refused], timeout: 5)
        XCTAssertNotNil(store.records["other"])
    }

    func testDeleteRefusesAnOutstandingPromptAndDoesNotCancelIt() {
        let opened = expectation(description: "existing prompt")
        vault.create(account: "agent", reason: "Set up") {
            if case .success(let session) = $0 { session.close() } else { XCTFail("existing prompt lost") }
            opened.fulfill()
        }
        let refused = expectation(description: "delete busy")
        vault.delete(account: "agent") {
            if case .failure(.busy) = $0 {} else { XCTFail("delete overlapped prompt") }
            refused.fulfill()
        }
        wait(for: [refused], timeout: 5)
        auth.succeed()
        wait(for: [opened], timeout: 5)
        XCTAssertNotNil(store.records["agent"])
    }

    func testRecoveryPrevalidationDoesNotPromptAndMapsErrorsWithoutDetails() throws {
        let material = EncryptedAgentMaterial(configJson: "{}", agentJson: "{}", publicKey: Data([1]),
            encryptedPrivateKey: Data([2]), algorithm: .pq2025)
        let failed = expectation(description: "bad paste")
        vault.receiveRecovery(material: material, code: "bad-paste", expectedAgentID: "test", expectedPublicKey: Data([1]),
            account: "agent", reason: "Restore") {
            if case .failure(.invalidRecoveryCode) = $0 {} else { XCTFail("untyped paste error") }
            failed.fulfill()
        }
        wait(for: [failed], timeout: 5)
        XCTAssertNil(auth.callback)
        XCTAssertTrue(store.records.isEmpty)
        for (code, expected) in [("InvalidPassword", JacsBiometricError.invalidRecoveryCode),
            ("MalformedKey", .identityMismatch), ("MalformedEnvelope", .malformedMaterial), ("Locked", .locked)] {
            let mapped = mapMobileError(MobileError.Core(code: code, detail: "sensitive-do-not-report"))
            XCTAssertEqual(mapped, expected)
            XCTAssertFalse(String(describing: mapped).contains("sensitive"))
        }
        let value = JacsBiometricRecovery(MobileRecoveryExport(code: "sensitive-code", material: material))
        XCTAssertFalse(String(describing: value).contains("sensitive-code"))
        XCTAssertFalse(String(reflecting: value).contains("sensitive-code"))
        XCTAssertTrue(Mirror(reflecting: value).children.isEmpty)
    }

    func testReadbackCancellationAndSignedDocumentLateResultAreSuppressed() {
        worker.suspend()
        let failed = expectation(description: "readback cancelled")
        let material = EncryptedAgentMaterial(configJson: "{}", agentJson: "{}", publicKey: Data([1]),
            encryptedPrivateKey: Data([2]), algorithm: .pq2025)
        let request = vault.verifyRecovery(material: material, code: "invalid", expectedAgentID: "test", expectedPublicKey: Data([1])) {
            if case .failure(.cancelled) = $0 {} else { XCTFail("late readback escaped") }
            failed.fulfill()
        }
        request.cancel()
        worker.resume()
        wait(for: [failed], timeout: 5)
        worker.sync {}; callbacks.sync {}
        let session = createSession()
        callbacks.suspend()
        let signed = expectation(description: "document cancelled")
        session.signDocumentJSON("exact-content") {
            if case .failure(.inactive) = $0 {} else { XCTFail("late complete document escaped") }
            signed.fulfill()
        }
        worker.sync {}
        vault.invalidate()
        callbacks.resume()
        wait(for: [signed], timeout: 5)
    }

    func testPreparedDocumentOwnedSessionSuppressesLateResultAndLockedDispatch() {
        let session = createSession()
        callbacks.suspend()
        let cancelled = expectation(description: "prepared document invalidated")
        session.signPreparedDocumentJSON("frozen-prepared-json") {
            if case .failure(.inactive) = $0 {} else { XCTFail("late prepared signature escaped") }
            cancelled.fulfill()
        }
        worker.sync {}
        XCTAssertEqual(factory.restored[0].signCalls, 1)
        vault.invalidate()
        callbacks.resume()
        wait(for: [cancelled], timeout: 5)
        let locked = expectation(description: "closed session refuses prepared signing")
        session.signPreparedDocumentJSON("frozen-prepared-json") {
            if case .failure(.inactive) = $0 {} else { XCTFail("closed session signed") }
            locked.fulfill()
        }
        wait(for: [locked], timeout: 5)
        XCTAssertEqual(factory.restored[0].signCalls, 1)
    }

    func testRecoveryLocksBeforeDeliveryAndCancellationSuppressesCode() {
        let session = createSession()
        callbacks.suspend()
        let done = expectation(description: "recovery result invalidated")
        session.createRecovery {
            if case .failure(.inactive) = $0 {} else { XCTFail("late recovery code escaped") }
            done.fulfill()
        }
        worker.sync {}
        XCTAssertFalse(session.isActive)
        XCTAssertTrue(factory.restored[0].cleared)
        session.close()
        callbacks.resume()
        wait(for: [done], timeout: 5)
    }

    func testRecoveryReturnsOnlyCodeAndEncryptedMaterialAfterLock() {
        let session = createSession()
        let originalRecord = store.records["agent"]
        let done = expectation(description: "recovery returned locked")
        session.createRecovery {
            guard case .success(let result) = $0 else { XCTFail("recovery failed"); done.fulfill(); return }
            XCTAssertEqual(result.code.count, 39)
            XCTAssertEqual(result.material.encryptedPrivateKey, Data([2]))
            XCTAssertFalse(session.isActive)
            XCTAssertTrue(self.factory.restored[0].cleared)
            done.fulfill()
        }
        wait(for: [done], timeout: 5)
        XCTAssertEqual(store.records["agent"], originalRecord)
    }

    func testClosingTransferBeforeQueuedDeliverySuppressesTheCode() {
        let session = createSession()
        callbacks.suspend()
        let done = expectation(description: "transfer result invalidated")
        session.createTransfer {
            if case .failure(.inactive) = $0 {} else { XCTFail("late transfer code escaped") }
            done.fulfill()
        }
        worker.sync {}
        XCTAssertFalse(session.isActive)
        XCTAssertTrue(factory.restored[0].cleared)
        session.close()
        callbacks.resume()
        wait(for: [done], timeout: 5)
    }

    func testEnrollmentDomainChangeAndBiometricDenialNeverImport() {
        createSession().close()
        auth = FakeAuthorization()
        auth.domainState = Data([9, 9, 9])
        let changed = expectation(description: "enrollment changed")
        vault.unlock(account: "agent", reason: "Unlock") {
            if case .failure(.notFoundOrEnrollmentChanged) = $0 {} else { XCTFail("domain change accepted") }
            changed.fulfill()
        }
        auth.succeed()
        wait(for: [changed], timeout: 5)
        XCTAssertEqual(factory.restored.count, 1)

        auth = FakeAuthorization()
        let denied = expectation(description: "biometry lockout")
        let reads = store.reads
        vault.unlock(account: "agent", reason: "Unlock") {
            if case .failure(.biometricsLockedOut) = $0 {} else { XCTFail("fallback allowed") }
            denied.fulfill()
        }
        auth.callback?(.failure(.biometricsLockedOut))
        wait(for: [denied], timeout: 5)
        XCTAssertEqual(store.reads, reads)
        XCTAssertEqual(factory.restored.count, 1)
    }

    func testOverlappingPromptIsRejectedWithoutCancellingFirstRequest() {
        let first = expectation(description: "first cancelled")
        let operation = vault.unlock(account: "agent", reason: "Unlock") {
            if case .failure(.cancelled) = $0 {} else { XCTFail("wrong first result") }
            first.fulfill()
        }
        auth = FakeAuthorization()
        let busy = expectation(description: "busy")
        vault.unlock(account: "agent", reason: "Unlock") {
            if case .failure(.busy) = $0 {} else { XCTFail("overlapping prompt accepted") }
            busy.fulfill()
        }
        operation.cancel()
        wait(for: [first, busy], timeout: 5)
        XCTAssertTrue(factory.restored.isEmpty)
    }

    func testRealRustPqCreateEncryptedExportUnlockAndSign() throws {
        // Only auth/persistence are faked here. Key creation, envelope KDF,
        // self-signature validation and signing run through the real UniFFI ABI.
        vault = JacsBiometricVault(store: store, factory: RustVaultAgentFactory(),
            authorization: { [unowned self] in self.auth }, callbacks: callbacks, worker: worker)
        let session = createSession()
        let exported = expectation(description: "real encrypted export")
        var material: EncryptedAgentMaterial?
        session.exportEncryptedMaterial(password: "Swift-vault-transfer-test-only!") {
            if case .success(let value) = $0 { material = value } else { XCTFail("export failed") }
            exported.fulfill()
        }
        wait(for: [exported], timeout: 15)
        let encrypted = try XCTUnwrap(material)
        XCTAssertEqual(encrypted.algorithm, .pq2025)
        let verifier = try MobileAgent.importEncryptedAgent(material: encrypted,
            password: "Swift-vault-transfer-test-only!")
        defer { try? verifier.clearSecrets() }
        session.close()

        auth = FakeAuthorization()
        let unlocked = expectation(description: "real Rust import")
        var restored: JacsBiometricSession?
        vault.unlock(account: "agent", reason: "Unlock") {
            if case .success(let value) = $0 { restored = value } else { XCTFail("unlock failed") }
            unlocked.fulfill()
        }
        auth.succeed()
        wait(for: [unlocked], timeout: 15)
        let restoredSession = try XCTUnwrap(restored)
        let signed = expectation(description: "real Rust signature")
        restoredSession.signMessageJSON("{\"swiftVault\":true}") {
            if case .success(let document) = $0 {
                XCTAssertTrue((try? verifier.verifyJson(json: document).valid) == true)
            } else { XCTFail("sign failed") }
            signed.fulfill()
        }
        wait(for: [signed], timeout: 15)
        let transferDone = expectation(description: "generated transfer relocks before delivery")
        var outbound: JacsBiometricTransfer?
        restoredSession.createTransfer {
            if case .success(let transfer) = $0 {
                outbound = transfer
                XCTAssertEqual(transfer.code.split(separator: " ").count, 6)
                XCTAssertEqual(transfer.material.algorithm, .pq2025)
                XCTAssertFalse(restoredSession.isActive)
                let received = try? MobileAgent.importEncryptedAgent(material: transfer.material,
                    password: transfer.code)
                XCTAssertNotNil(received)
                XCTAssertEqual(try? received?.publicKey(), try? verifier.publicKey())
                try? received?.clearSecrets()
            } else { XCTFail("transfer failed") }
            transferDone.fulfill()
        }
        wait(for: [transferDone], timeout: 15)
        let transfer = try XCTUnwrap(outbound)
        let identityData = Data(try verifier.exportAgentJson().utf8)
        let identity = try XCTUnwrap(JSONSerialization.jsonObject(with: identityData) as? [String: Any])
        let agentID = try XCTUnwrap(identity["jacsId"] as? String)
        let publicKey = try verifier.publicKey()

        auth = FakeAuthorization()
        let received = expectation(description: "pinned transfer immediately rewrapped")
        vault.receive(material: transfer.material, code: transfer.code,
            expectedAgentID: agentID, expectedPublicKey: publicKey,
            account: "received", reason: "Receive identity") {
            if case .success(let session) = $0 { session.close() } else { XCTFail("pinned receive failed") }
            received.fulfill()
        }
        auth.succeed()
        wait(for: [received], timeout: 15)
        XCTAssertNotNil(store.records["received"])

        auth = FakeAuthorization()
        let wrongPin = expectation(description: "wrong key never persisted")
        vault.receive(material: transfer.material, code: transfer.code,
            expectedAgentID: agentID, expectedPublicKey: Data([0]),
            account: "wrong-pin", reason: "Receive identity") {
            if case .failure = $0 {} else { XCTFail("wrong pin accepted") }
            wrongPin.fulfill()
        }
        auth.succeed()
        wait(for: [wrongPin], timeout: 15)
        XCTAssertNil(store.records["wrong-pin"])
    }
}
