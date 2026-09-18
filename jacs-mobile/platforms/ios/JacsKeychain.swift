import Foundation
import LocalAuthentication
import Security
import CryptoKit
import JacsMobile

/// Default custody path for transferable ML-DSA-87 (pq2025) identities.
/// Biometrics gate the wrapping password; ML-DSA signing stays in portable Rust.
/// Stores only a random envelope password behind Keychain biometric access.
/// Store materialToJson(...) separately; that JSON contains encrypted keys.
/// This class never puts a signing private key into Swift or Keychain directly.
@available(iOS 13.0, *)
public final class JacsKeychain {
    private let service: String
    public init(service: String) { self.service = service }

    public enum StoreError: Error {
        case status(OSStatus)
        case malformedSecret
    }

    private func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    /// Create and save a CSPRNG envelope password. Existing entries are never
    /// silently replaced. Persist returned encrypted material before closing
    /// the agent; remove this entry if that persistence fails.
    public func protect(agent: MobileAgent, account: String) throws -> EncryptedAgentMaterial {
        var bytes = Data(count: 32)
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw StoreError.status(status) }
        // The base64 password is identical on both sides of the FFI boundary.
        // Swift String/FFI copies cannot be reliably wiped; keep them short-lived.
        let secret = bytes.base64EncodedString()
        let material = try agent.exportEncryptedAgent(password: secret)
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet, &accessError
        ) else {
            if let error = accessError { throw error.takeRetainedValue() }
            throw StoreError.status(errSecParam)
        }
        var item = query(account)
        item[kSecAttrAccessControl as String] = access
        item[kSecValueData as String] = Data(secret.utf8)
        item[kSecAttrSynchronizable as String] = false
        let added = SecItemAdd(item as CFDictionary, nil)
        guard added == errSecSuccess else { throw StoreError.status(added) }
        return material
    }

    /// Call on a worker queue. Keychain requests biometric authorization using
    /// this context; NSFaceIDUsageDescription is required in the app Info.plist.
    public func unlock(material: EncryptedAgentMaterial, account: String,
                       reason: String) throws -> MobileAgent {
        let context = LAContext()
        defer { context.invalidate() }
        context.localizedReason = reason
        var item = query(account)
        item[kSecReturnData as String] = true
        item[kSecMatchLimit as String] = kSecMatchLimitOne
        item[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(item as CFDictionary, &result)
        guard status == errSecSuccess else { throw StoreError.status(status) }
        guard var bytes = result as? Data,
              let password = String(data: bytes, encoding: .utf8) else {
            throw StoreError.malformedSecret
        }
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        return try MobileAgent.importEncryptedAgent(material: material, password: password)
    }

    public func delete(account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw StoreError.status(status)
        }
    }
}

/// Explicit classical-compatibility option, not the default identity mode.
/// Non-transferable Secure Enclave ES256 signer. Persist its application tag
/// and signed agent document; recreate a MobileAgent after it is cleared.
/// The private key never leaves Secure Enclave. This intentionally cannot be
/// used for phone-to-browser key transfer: use JacsKeychain for that mode.
@available(iOS 13.0, *)
public final class JacsSecureEnclaveSigner: PlatformSigner, @unchecked Sendable {
    private var key: SecKey?
    private let encodedPublicKey: Data
    private let context: LAContext
    private let lock = NSLock()

    private init(key: SecKey, context: LAContext) throws {
        // Never infer hardware custody from an application tag or EC key type.
        // Validate references from BOTH creation and lookup before exposing them.
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrKeyClass as String] as? String == kSecAttrKeyClassPrivate as String,
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String,
              (attributes[kSecAttrKeySizeInBits as String] as? NSNumber)?.intValue == 256 else {
            context.invalidate()
            throw PlatformSignerError.Unavailable(detail: "Expected a private Secure Enclave P-256 key")
        }
        self.key = key
        self.context = context
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw PlatformSignerError.Unavailable(detail: "Secure Enclave public key unavailable")
        }
        var error: Unmanaged<CFError>?
        guard let bytes = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw PlatformSignerError.Unavailable(detail: "Unable to encode public key")
        }
        encodedPublicKey = bytes
    }

    public static func create(tag: Data, reason: String) throws -> JacsSecureEnclaveSigner {
        let context = LAContext()
        context.localizedReason = reason
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], &error
        ) else { throw PlatformSignerError.Unavailable(detail: "Biometric access control unavailable") }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access],
            kSecUseAuthenticationContext as String: context]
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw PlatformSignerError.Unavailable(detail: "Secure Enclave key creation failed")
        }
        return try Self(key: key, context: context)
    }

    public static func load(tag: Data, reason: String) throws -> JacsSecureEnclaveSigner {
        let context = LAContext()
        context.localizedReason = reason
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let result = result, CFGetTypeID(result) == SecKeyGetTypeID() else {
            context.invalidate()
            throw PlatformSignerError.Unavailable(detail: "Secure Enclave key unavailable")
        }
        return try Self(key: result as! SecKey, context: context)
    }

    public func algorithm() -> MobileAlgorithm { .es256 }
    public func publicKey() throws -> Data { encodedPublicKey }
    public func sign(message: Data) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        guard let key = key else { throw PlatformSignerError.AuthenticationRequired }
        var error: Unmanaged<CFError>?
        // Message algorithm hashes once; do not pre-hash the message in Swift.
        guard let der = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                              message as CFData, &error) as Data? else {
            if let error = error?.takeRetainedValue() {
                let code = CFErrorGetCode(error)
                if code == errSecUserCanceled { throw PlatformSignerError.Cancelled }
                if code == errSecAuthFailed || code == errSecInteractionNotAllowed {
                    throw PlatformSignerError.AuthenticationRequired
                }
            }
            throw PlatformSignerError.Failed(detail: "Secure Enclave signing failed")
        }
        do {
            return try P256.Signing.ECDSASignature(derRepresentation: der).rawRepresentation
        } catch {
            throw PlatformSignerError.Failed(detail: "Malformed Secure Enclave signature")
        }
    }
    public func clearSecrets() {
        lock.lock()
        defer { lock.unlock() }
        key = nil
        context.invalidate()
    }
}
