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

    @Test func decodingTypeMismatchAlsoMeansCorruptedStore() {
        let error = DecodingError.typeMismatch(
            String.self,
            .init(codingPath: [], debugDescription: "expected string value")
        )
        #expect(ErrorFormatting.userMessage(for: error) == "Encrypted store is corrupted or unreadable.")
    }

    @Test func invalidSecretKeyInEncryptedStoreStaysReadable() {
        let error = StoreError.invalidSecretKey("BAD-KEY")
        #expect(
            ErrorFormatting.userMessage(for: error) ==
            "Encrypted store contains invalid key 'BAD-KEY'. Secret names must match [A-Za-z_][A-Za-z0-9_]*."
        )
    }

    @Test func missingFileUsesReadablePathMessage() {
        let error = NSError(
            domain: NSCocoaErrorDomain,
            code: CocoaError.fileReadNoSuchFile.rawValue,
            userInfo: [NSFilePathErrorKey: "/tmp/.env"]
        )
        #expect(ErrorFormatting.userMessage(for: error) == "File not found: /tmp/.env")
    }

    @Test func readPermissionDeniedIncludesPath() {
        let error = NSError(
            domain: NSCocoaErrorDomain,
            code: CocoaError.fileReadNoPermission.rawValue,
            userInfo: [NSFilePathErrorKey: "/etc/secrets.env"]
        )
        #expect(ErrorFormatting.userMessage(for: error) == "Permission denied while reading /etc/secrets.env.")
    }

    @Test func readPermissionDeniedWithoutPathFallsBack() {
        let error = NSError(
            domain: NSCocoaErrorDomain,
            code: CocoaError.fileReadNoPermission.rawValue,
            userInfo: [:]
        )
        #expect(ErrorFormatting.userMessage(for: error) == "Permission denied while reading the file.")
    }

    @Test func writePermissionDeniedIncludesPath() {
        let error = NSError(
            domain: NSCocoaErrorDomain,
            code: CocoaError.fileWriteNoPermission.rawValue,
            userInfo: [NSFilePathErrorKey: "/root/.bioenv/abc123.enc"]
        )
        #expect(ErrorFormatting.userMessage(for: error) == "Permission denied while writing /root/.bioenv/abc123.enc.")
    }

    @Test func writePermissionDeniedWithoutPathFallsBack() {
        let error = NSError(
            domain: NSCocoaErrorDomain,
            code: CocoaError.fileWriteNoPermission.rawValue,
            userInfo: [:]
        )
        #expect(ErrorFormatting.userMessage(for: error) == "Permission denied while writing the file.")
    }

    @Test func envFileParseErrorsStaySpecific() {
        let error = EnvFileParseError(
            path: "/tmp/.env",
            line: 7,
            key: "PRIVATE_KEY",
            message: "unterminated quoted value"
        )
        #expect(
            ErrorFormatting.userMessage(for: error) ==
            "Invalid .env file at /tmp/.env:7 for key 'PRIVATE_KEY': unterminated quoted value"
        )
    }

    @Test func execUsageErrorsStayReadable() {
        #expect(
            ErrorFormatting.userMessage(for: ExecError.invalidUsage) ==
            "Usage: bioenv exec -- COMMAND [ARGS...]"
        )
    }

    @Test func execNulValueErrorsStayReadable() {
        #expect(
            ErrorFormatting.userMessage(for: ExecError.invalidEnvironmentEntry(key: "PRIVATE_KEY")) ==
            "Cannot exec with value for 'PRIVATE_KEY' because it contains a NUL byte."
        )
    }

    @Test func execNulArgumentErrorsStayReadable() {
        #expect(
            ErrorFormatting.userMessage(for: ExecError.invalidCommandArgument(index: 1)) ==
            "Cannot exec because command argument 2 contains a NUL byte."
        )
    }

    @Test func unrelatedErrorsFallBackToLocalizedDescription() {
        struct SampleError: LocalizedError {
            var errorDescription: String? { "sample failure" }
        }

        #expect(ErrorFormatting.userMessage(for: SampleError()) == "sample failure")
    }
}
