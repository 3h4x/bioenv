import Foundation
import Testing
import bioenvLib

@Suite("Crypto")
struct CryptoTests {
    private func makeKey(_ count: Int = 32) -> Data {
        Data((0..<count).map { UInt8($0 & 0xFF) })
    }

    // MARK: - Round-trips

    @Test func roundTripBasic() throws {
        let key = makeKey()
        let plaintext = Data("hello, world".utf8)
        let ciphertext = try Crypto.encrypt(data: plaintext, key: key)
        let decrypted = try Crypto.decrypt(data: ciphertext, key: key)
        #expect(decrypted == plaintext)
    }

    @Test func roundTripEmpty() throws {
        let key = makeKey()
        let ciphertext = try Crypto.encrypt(data: Data(), key: key)
        let decrypted = try Crypto.decrypt(data: ciphertext, key: key)
        #expect(decrypted == Data())
    }

    @Test func roundTripLargePayload() throws {
        let key = makeKey()
        let plaintext = Data(repeating: 0xAB, count: 64_000)
        let ciphertext = try Crypto.encrypt(data: plaintext, key: key)
        let decrypted = try Crypto.decrypt(data: ciphertext, key: key)
        #expect(decrypted == plaintext)
    }

    @Test func roundTripArbitraryBytes() throws {
        let key = makeKey()
        let plaintext = Data((0..<256).map { UInt8($0) })
        let ciphertext = try Crypto.encrypt(data: plaintext, key: key)
        let decrypted = try Crypto.decrypt(data: ciphertext, key: key)
        #expect(decrypted == plaintext)
    }

    // MARK: - Non-determinism (AES-GCM uses a random nonce)

    @Test func encryptProducesDifferentCiphertextsEachTime() throws {
        let key = makeKey()
        let plaintext = Data("same input".utf8)
        let ct1 = try Crypto.encrypt(data: plaintext, key: key)
        let ct2 = try Crypto.encrypt(data: plaintext, key: key)
        #expect(ct1 != ct2)
    }

    // MARK: - Wrong key

    @Test func wrongKeyThrowsDecryptionError() throws {
        let key1 = makeKey(32)
        let key2 = Data(repeating: 0xFF, count: 32)
        let ciphertext = try Crypto.encrypt(data: Data("secret".utf8), key: key1)
        #expect(throws: (any Error).self) {
            try Crypto.decrypt(data: ciphertext, key: key2)
        }
    }

    // MARK: - Corrupted ciphertext

    @Test func truncatedCiphertextThrows() throws {
        let key = makeKey()
        let ciphertext = try Crypto.encrypt(data: Data("data".utf8), key: key)
        // AES-GCM combined = 12-byte nonce + ciphertext + 16-byte tag; truncate the tag
        let truncated = ciphertext.prefix(ciphertext.count - 4)
        #expect(throws: (any Error).self) {
            try Crypto.decrypt(data: Data(truncated), key: key)
        }
    }

    @Test func flippedBitInCiphertextThrows() throws {
        let key = makeKey()
        let plaintext = Data("authentic".utf8)
        var ciphertext = try Crypto.encrypt(data: plaintext, key: key)
        // Flip a bit in the ciphertext body (past the 12-byte nonce)
        ciphertext[15] ^= 0x01
        #expect(throws: (any Error).self) {
            try Crypto.decrypt(data: ciphertext, key: key)
        }
    }

    @Test func emptyCiphertextThrows() throws {
        let key = makeKey()
        #expect(throws: (any Error).self) {
            try Crypto.decrypt(data: Data(), key: key)
        }
    }

    // MARK: - Key size sensitivity

    @Test func mismatchedKeySizeFailsToDecrypt() throws {
        let shortKey = makeKey(16)
        let fullKey = makeKey(32)
        let ciphertext = try Crypto.encrypt(data: Data("payload".utf8), key: shortKey)
        #expect(throws: (any Error).self) {
            try Crypto.decrypt(data: ciphertext, key: fullKey)
        }
    }

    // MARK: - Decryption error type

    @Test func wrongKeyThrowsCryptoError() throws {
        let key1 = Data(repeating: 0xAA, count: 32)
        let key2 = Data(repeating: 0xBB, count: 32)
        let ciphertext = try Crypto.encrypt(data: Data("x".utf8), key: key1)
        do {
            _ = try Crypto.decrypt(data: ciphertext, key: key2)
            Issue.record("Expected decryption to fail")
        } catch let error as CryptoError {
            if case .decryptionFailed = error {
                // expected
            } else {
                Issue.record("Expected .decryptionFailed, got \(error)")
            }
        } catch {
            Issue.record("Expected CryptoError, got \(error)")
        }
    }

    // MARK: - Invalid key sizes (AES requires 128, 192, or 256-bit keys)

    @Test func encryptWith0ByteKeyThrows() {
        #expect(throws: (any Error).self) {
            try Crypto.encrypt(data: Data("x".utf8), key: Data())
        }
    }

    @Test func encryptWith1ByteKeyThrows() {
        #expect(throws: (any Error).self) {
            try Crypto.encrypt(data: Data("x".utf8), key: Data([0x42]))
        }
    }

    @Test func encryptWith8ByteKeyThrows() {
        #expect(throws: (any Error).self) {
            try Crypto.encrypt(data: Data("x".utf8), key: Data(repeating: 0x42, count: 8))
        }
    }

    @Test func encryptWith17ByteKeyThrows() {
        #expect(throws: (any Error).self) {
            try Crypto.encrypt(data: Data("x".utf8), key: Data(repeating: 0x42, count: 17))
        }
    }

    @Test func encryptWith31ByteKeyThrows() {
        #expect(throws: (any Error).self) {
            try Crypto.encrypt(data: Data("x".utf8), key: Data(repeating: 0x42, count: 31))
        }
    }

    @Test func invalidKeySizeThrowsEncryptionFailed() throws {
        do {
            _ = try Crypto.encrypt(data: Data("payload".utf8), key: Data([0x01]))
            Issue.record("Expected encryption to fail with 1-byte key")
        } catch let error as CryptoError {
            if case .encryptionFailed = error {
                // expected — CryptoKit rejects non-AES key sizes; our wrapper surfaces them as .encryptionFailed
            } else {
                Issue.record("Expected .encryptionFailed, got \(error)")
            }
        } catch {
            Issue.record("Expected CryptoError, got \(error)")
        }
    }

    @Test func decryptWith1ByteKeyThrows() throws {
        // Valid ciphertext produced with a 16-byte key; decrypting with a 1-byte key must fail.
        let validKey = makeKey(16)
        let ciphertext = try Crypto.encrypt(data: Data("secret".utf8), key: validKey)
        #expect(throws: (any Error).self) {
            try Crypto.decrypt(data: ciphertext, key: Data([0x42]))
        }
    }

    @Test func decryptWith0ByteKeyThrows() throws {
        let validKey = makeKey(32)
        let ciphertext = try Crypto.encrypt(data: Data("secret".utf8), key: validKey)
        #expect(throws: (any Error).self) {
            try Crypto.decrypt(data: ciphertext, key: Data())
        }
    }

    @Test func valid16ByteKeyRoundTrips() throws {
        // AES-128-GCM is valid — 16-byte key should work end-to-end.
        let key = makeKey(16)
        let plaintext = Data("aes128 works".utf8)
        let ciphertext = try Crypto.encrypt(data: plaintext, key: key)
        let decrypted = try Crypto.decrypt(data: ciphertext, key: key)
        #expect(decrypted == plaintext)
    }

    @Test func valid24ByteKeyRoundTrips() throws {
        // AES-192-GCM is valid — 24-byte key should work end-to-end.
        let key = makeKey(24)
        let plaintext = Data("aes192 works".utf8)
        let ciphertext = try Crypto.encrypt(data: plaintext, key: key)
        let decrypted = try Crypto.decrypt(data: ciphertext, key: key)
        #expect(decrypted == plaintext)
    }

    // MARK: - Error descriptions

    @Test func encryptionErrorDescriptionContainsMessage() {
        let err = CryptoError.encryptionFailed("sealed box unavailable")
        #expect(err.description == "Encryption failed: sealed box unavailable")
    }

    @Test func decryptionErrorDescriptionContainsMessage() {
        let err = CryptoError.decryptionFailed("authentication tag mismatch")
        #expect(err.description == "Decryption failed: authentication tag mismatch")
    }
}
