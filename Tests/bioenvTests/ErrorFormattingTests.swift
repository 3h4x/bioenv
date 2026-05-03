import Foundation
import Security
import Testing
import bioenvLib

@Suite("ErrorFormatting")
struct ErrorFormattingTests {
    @Test func keychainNotInitializedMessageIsFriendly() {
        let error = KeychainError("Failed to retrieve encryption key", status: errSecItemNotFound)
        #expect(ErrorFormatting.userMessage(for: error) == "bioenv is not initialized for this project. Run 'bioenv init' first.")
    }

    @Test func keychainAuthFailureDropsFrameworkDetails() {
        let error = KeychainError("Authentication failed: The operation couldn’t be completed.")
        #expect(ErrorFormatting.userMessage(for: error) == "Authentication failed.")
    }

    @Test func keychainStatusFailuresPreserveOSStatus() {
        let error = KeychainError("Failed to store key in Keychain", status: errSecDuplicateItem)
        #expect(ErrorFormatting.userMessage(for: error) == "Failed to store key in Keychain (OSStatus: \(errSecDuplicateItem))")
    }

    @Test func cryptoDecryptionFailureIsGeneralized() {
        let error = CryptoError.decryptionFailed("The operation couldn’t be completed. (CryptoKit error 7.)")
        #expect(ErrorFormatting.userMessage(for: error) == "Failed to decrypt secrets. The encrypted store may be corrupted or the wrong Keychain key may be in use.")
    }

    @Test func cryptoInvalidKeySizeSuggestsRecoveryPath() {
        let error = CryptoError.invalidKeySize(16)
        #expect(ErrorFormatting.userMessage(for: error) == "Stored encryption key is invalid for this project.")
    }

    @Test func decodingErrorMeansCorruptedStore() {
        let error = DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "bad json"))
        #expect(ErrorFormatting.userMessage(for: error) == "Encrypted store is corrupted or unreadable.")
    }

    @Test func missingFileUsesReadablePathMessage() {
        let error = NSError(
            domain: NSCocoaErrorDomain,
            code: CocoaError.fileReadNoSuchFile.rawValue,
            userInfo: [NSFilePathErrorKey: "/tmp/.env"]
        )
        #expect(ErrorFormatting.userMessage(for: error) == "File not found: /tmp/.env")
    }

    @Test func unrelatedErrorsFallBackToLocalizedDescription() {
        struct SampleError: LocalizedError {
            var errorDescription: String? { "sample failure" }
        }

        #expect(ErrorFormatting.userMessage(for: SampleError()) == "sample failure")
    }
}
