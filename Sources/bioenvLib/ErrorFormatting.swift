import Foundation
import Security

public enum ErrorFormatting {
    public static func userMessage(for error: any Error) -> String {
        if let envFileError = error as? EnvFileParseError {
            return envFileError.description
        }

        if let keychainError = error as? KeychainError {
            return formatKeychainError(keychainError)
        }

        if let cryptoError = error as? CryptoError {
            return formatCryptoError(cryptoError)
        }

        if let storeError = error as? StoreError {
            return formatStoreError(storeError)
        }

        if let execError = error as? ExecError {
            return execError.description
        }

        if error is DecodingError {
            return "Encrypted store is corrupted or unreadable."
        }

        let nsError = error as NSError
        if nsError.domain == NSCocoaErrorDomain {
            switch CocoaError.Code(rawValue: nsError.code) {
            case .fileReadNoSuchFile:
                return "File not found: \(nsError.userInfo[NSFilePathErrorKey] as? String ?? nsError.localizedDescription)"
            case .fileReadNoPermission:
                return "Permission denied while reading \(nsError.userInfo[NSFilePathErrorKey] as? String ?? "the file")."
            case .fileWriteNoPermission:
                return "Permission denied while writing \(nsError.userInfo[NSFilePathErrorKey] as? String ?? "the file")."
            default:
                break
            }
        }

        return error.localizedDescription
    }

    private static func formatKeychainError(_ error: KeychainError) -> String {
        switch error.status {
        case errSecItemNotFound:
            return "bioenv is not initialized for this project. Run 'bioenv init' first."
        case errSecAuthFailed:
            return "Authentication failed."
        default:
            break
        }

        if error.message.hasPrefix("Authentication failed:") {
            return "Authentication failed."
        }

        return error.description
    }

    private static func formatCryptoError(_ error: CryptoError) -> String {
        switch error {
        case .invalidKeySize:
            return "Stored encryption key is invalid for this project."
        case .encryptionFailed:
            return "Failed to encrypt secrets."
        case .decryptionFailed:
            return "Failed to decrypt secrets. The encrypted store may be corrupted or the wrong Keychain key may be in use."
        }
    }

    private static func formatStoreError(_ error: StoreError) -> String {
        switch error {
        case .invalidSecretKey(let key):
            return "Encrypted store contains invalid key '\(key)'. Secret names must match [A-Za-z_][A-Za-z0-9_]*."
        }
    }
}
