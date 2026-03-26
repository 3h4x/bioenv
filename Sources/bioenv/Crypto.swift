import Foundation
import CryptoKit

enum CryptoError: Error, CustomStringConvertible {
    case encryptionFailed(String)
    case decryptionFailed(String)

    var description: String {
        switch self {
        case .encryptionFailed(let msg): return "Encryption failed: \(msg)"
        case .decryptionFailed(let msg): return "Decryption failed: \(msg)"
        }
    }
}

enum Crypto {
    static func encrypt(data: Data, key: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        do {
            let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
            guard let combined = sealedBox.combined else {
                throw CryptoError.encryptionFailed("Failed to get combined representation")
            }
            return combined
        } catch let error as CryptoError {
            throw error
        } catch {
            throw CryptoError.encryptionFailed(error.localizedDescription)
        }
    }

    static func decrypt(data: Data, key: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: data)
            return try AES.GCM.open(sealedBox, using: symmetricKey)
        } catch {
            throw CryptoError.decryptionFailed(error.localizedDescription)
        }
    }
}
