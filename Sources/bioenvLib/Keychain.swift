import Foundation
import Security
import LocalAuthentication

public struct KeychainError: Error, CustomStringConvertible {
    public let message: String
    public let status: OSStatus?

    public init(_ message: String, status: OSStatus? = nil) {
        self.message = message
        self.status = status
    }

    public var description: String {
        if let status = status {
            return "\(message) (OSStatus: \(status))"
        }
        return message
    }
}

public enum Keychain {
    public static func serviceName(for projectHash: String) -> String {
        "com.bioenv.\(projectHash)"
    }

    /// Holds the result of an LAContext.evaluatePolicy callback.
    /// Marked @unchecked Sendable because a DispatchSemaphore provides the
    /// ordering guarantee (write-then-signal / wait-then-read), so concurrent
    /// access never actually occurs in practice.
    private final class AuthResult: @unchecked Sendable {
        var authenticated = false
        var error: NSError?
    }

    /// Authenticate the user with Touch ID / password before accessing secrets.
    public static func authenticate(reason: String) throws {
        let context = LAContext()
        var canEvalError: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &canEvalError) else {
            throw KeychainError("Biometric authentication not available: \(canEvalError?.localizedDescription ?? "unknown")")
        }

        let result = AuthResult()
        let semaphore = DispatchSemaphore(value: 0)

        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, evalError in
            result.authenticated = success
            result.error = evalError as? NSError
            semaphore.signal()
        }

        // 60-second cap so a hung LAContext callback doesn't block the process forever.
        guard semaphore.wait(timeout: .now() + .seconds(60)) == .success else {
            throw KeychainError("Authentication timed out")
        }

        guard result.authenticated else {
            throw KeychainError("Authentication failed: \(result.error?.localizedDescription ?? "unknown")")
        }
    }

    public static func getOrCreateKey(projectHash: String, syncable: Bool = false) throws -> Data {
        do {
            return try getKey(projectHash: projectHash)
        } catch let e as KeychainError where e.status == errSecItemNotFound {
            return try createKey(projectHash: projectHash, syncable: syncable)
        }
    }

    public static func hasKey(projectHash: String) throws -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName(for: projectHash),
            kSecAttrAccount as String: "encryption-key",
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        if status == errSecItemNotFound {
            return false
        }
        guard status == errSecSuccess else {
            throw KeychainError("Failed to check for encryption key", status: status)
        }

        return true
    }

    public static func getKey(projectHash: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName(for: projectHash),
            kSecAttrAccount as String: "encryption-key",
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            throw KeychainError("No encryption key found for this project — run 'bioenv init' first", status: errSecItemNotFound)
        }
        guard status == errSecSuccess else {
            throw KeychainError("Failed to retrieve encryption key", status: status)
        }
        guard let keyData = result as? Data else {
            throw KeychainError("Keychain returned unexpected data type for encryption key")
        }

        return keyData
    }

    public static func createKey(projectHash: String, syncable: Bool = false) throws -> Data {
        var keyBytes = [UInt8](repeating: 0, count: 32)
        // Zero the stack buffer on exit regardless of success or failure path.
        defer { for i in 0..<keyBytes.count { keyBytes[i] = 0 } }
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

    public static func deleteKey(projectHash: String) throws {
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
