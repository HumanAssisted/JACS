import XCTest
import Security
import LocalAuthentication
@testable import JacsMobilePlatform

/// Actual simulator Keychain calls, without pretending to exercise Face ID.
/// The foreground biometric/device acceptance run is documented separately.
final class JacsKeychainPolicyTests: XCTestCase {
    private final class Context: JacsBiometricAuthorizing {
        let native = LAContext()
        var context: LAContext? { native }
        var domainState: Data? { Data([1]) }
        func authenticate(reason: String, completion: @escaping (Result<Void, JacsBiometricError>) -> Void) {
            XCTFail("these negative policy tests must not prompt")
        }
        func invalidate() { native.invalidate() }
    }

    func testWeakerLegacyRecordCannotBeReadThroughBiometricVault() throws {
        let service = "jacs-policy-test-" + UUID().uuidString
        let store = SystemVaultRecordStore(service: service)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: store.service,
            kSecAttrAccount as String: "agent",
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true]
        var item = query
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        item[kSecValueData as String] = Data("weaker-item".utf8)
        let status = SecItemAdd(item as CFDictionary, nil)
        XCTAssertEqual(status, errSecSuccess)
        guard status == errSecSuccess else { return }
        defer { SecItemDelete(query as CFDictionary) }
        XCTAssertThrowsError(try store.read(account: "agent", authorization: Context())) {
            XCTAssertEqual($0 as? JacsBiometricError, .invalidStoredRecord)
        }
        XCTAssertThrowsError(try store.read(account: "different", authorization: Context())) {
            XCTAssertEqual($0 as? JacsBiometricError, .notFoundOrEnrollmentChanged)
        }
    }

    func testMissingRecordDoesNotInventOrReplaceIdentity() {
        let store = SystemVaultRecordStore(service: "jacs-missing-test-" + UUID().uuidString)
        XCTAssertThrowsError(try store.read(account: "missing", authorization: Context())) {
            XCTAssertEqual($0 as? JacsBiometricError, .notFoundOrEnrollmentChanged)
        }
    }
}
