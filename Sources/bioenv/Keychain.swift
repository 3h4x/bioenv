import Foundation
import Security
import LocalAuthentication

struct KeychainError: Error, CustomStringConvertible {
    let message: String
    let status: OSStatus?

    init(_ message: String, status: OSStatus? = nil) {
        self.message = message
        self.status = status
    }

    var description: String {
        if let status = status {
            return "\(message) (OSStatus: \(status))"
        }
        return message
    }
}

enum Keychain {
    private static func serviceName(for projectHash: String) -> String {
        "com.bioenv.\(projectHash)"
    }

    /// Authenticate the user with Touch ID / password before accessing secrets.
    static func authenticate(reason: String) throws {
        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw KeychainError("Biometric authentication not available: \(error?.localizedDescription ?? "unknown")")
        }

        var authError: NSError?
        var authenticated = false
        let semaphore = DispatchSemaphore(value: 0)

        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, evalError in
            authenticated = success
            authError = evalError as? NSError
            semaphore.signal()
        }

        semaphore.wait()

        guard authenticated else {
            throw KeychainError("Authentication failed: \(authError?.localizedDescription ?? "unknown")")
        }
    }

static func getOrCreateKey(projectHash: String, syncable: Bool = false) throws -> Data {
        if let existing = try? getKey(projectHash: projectHash) {
            return existing
        }
        return try createKey(projectHash: projectHash, syncable: syncable)
    }

    static func getKey(projectHash: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName(for: projectHash),
            kSecAttrAccount as String: "encryption-key",
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let keyData = result as? Data else {
            throw KeychainError("Failed to retrieve key", status: status)
        }

        return keyData
    }

    static func createKey(projectHash: String, syncable: Bool = false) throws -> Data {
        var keyBytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, keyBytes.count, &keyBytes)
        guard status == errSecSuccess else {
            throw KeychainError("Failed to generate random key", status: status)
        }

        let keyData = Data(keyBytes)
        let service = serviceName(for: projectHash)

        let accessibility = syncable
            ? kSecAttrAccessibleWhenUnlocked
            : kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "encryption-key",
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: accessibility,
            kSecAttrSynchronizable as String: syncable,
        ]

        let addStatus = SecItemAdd(query as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KeychainError("Failed to store key in Keychain", status: addStatus)
        }

        return keyData
    }

    static func deleteKey(projectHash: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName(for: projectHash),
            kSecAttrAccount as String: "encryption-key",
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError("Failed to delete key", status: status)
        }
    }
}
