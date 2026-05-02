import Foundation
import CryptoKit

public enum CryptoError: Error, CustomStringConvertible {
    case invalidKeySize(Int)
    case encryptionFailed(String)
    case decryptionFailed(String)

    public var description: String {
        switch self {
        case .invalidKeySize(let size): return "Invalid key size: expected 32 bytes for AES-256-GCM, got \(size)"
        case .encryptionFailed(let msg): return "Encryption failed: \(msg)"
        case .decryptionFailed(let msg): return "Decryption failed: \(msg)"
        }
    }
}

public enum Crypto {
    private static let aes256KeySize = 32

    public static func encrypt(data: Data, key: Data) throws -> Data {
        try validateKeySize(key)
        let symmetricKey = SymmetricKey(data: key)
        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.seal(data, using: symmetricKey)
        } catch {
            throw CryptoError.encryptionFailed(error.localizedDescription)
        }
        guard let combined = sealedBox.combined else {
            throw CryptoError.encryptionFailed("Failed to get combined representation")
        }
        return combined
    }

    public static func decrypt(data: Data, key: Data) throws -> Data {
        try validateKeySize(key)
        let symmetricKey = SymmetricKey(data: key)
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: data)
            return try AES.GCM.open(sealedBox, using: symmetricKey)
        } catch {
            throw CryptoError.decryptionFailed(error.localizedDescription)
        }
    }

    private static func validateKeySize(_ key: Data) throws {
        guard key.count == aes256KeySize else {
            throw CryptoError.invalidKeySize(key.count)
        }
    }
}
