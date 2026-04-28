import Foundation
import Security
import Testing
import bioenvLib

// MARK: - Integration tests (require a macOS Keychain; no Touch ID needed)

/// These tests call SecItem* APIs directly on the macOS Keychain.
/// They do NOT require Touch ID — only an unlocked Keychain (standard on any interactive Mac session).
/// Each test generates a unique project hash so it never conflicts with real bioenv entries.
@Suite("Keychain.CRUD", .serialized)
struct KeychainCRUDTests {
    private func uniqueHash() -> String {
        String(UUID().uuidString.lowercased().filter { $0.isHexDigit }.prefix(16))
    }

    @Test func createKeyReturns32Bytes() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        let key = try Keychain.createKey(projectHash: hash)
        #expect(key.count == 32)
    }

    @Test func getKeyRetrievesSameKeyAsCreated() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        let created = try Keychain.createKey(projectHash: hash)
        let retrieved = try Keychain.getKey(projectHash: hash)
        #expect(created == retrieved)
    }

    @Test func getKeyThrowsKeyNotFoundError() {
        let hash = uniqueHash()
        do {
            _ = try Keychain.getKey(projectHash: hash)
            Issue.record("Expected KeychainError to be thrown")
        } catch let e as KeychainError {
            #expect(e.status == errSecItemNotFound)
        } catch {
            Issue.record("Expected KeychainError, got \(error)")
        }
    }

    @Test func deleteKeyRemovesExistingKey() throws {
        let hash = uniqueHash()
        _ = try Keychain.createKey(projectHash: hash)
        try Keychain.deleteKey(projectHash: hash)
        #expect(throws: (any Error).self) {
            try Keychain.getKey(projectHash: hash)
        }
    }

    @Test func deleteKeyIsIdempotentForMissingKey() {
        let hash = uniqueHash()
        #expect(throws: Never.self) {
            try Keychain.deleteKey(projectHash: hash)
        }
    }

    @Test func getOrCreateKeyCreatesKeyWhenMissing() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        let key = try Keychain.getOrCreateKey(projectHash: hash)
        #expect(key.count == 32)
    }

    @Test func getOrCreateKeyReturnsSameKeyOnSubsequentCalls() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        let first = try Keychain.getOrCreateKey(projectHash: hash)
        let second = try Keychain.getOrCreateKey(projectHash: hash)
        #expect(first == second)
    }

    @Test func createdKeysAreRandom() throws {
        let hash1 = uniqueHash()
        let hash2 = uniqueHash()
        defer {
            try? Keychain.deleteKey(projectHash: hash1)
            try? Keychain.deleteKey(projectHash: hash2)
        }
        let key1 = try Keychain.createKey(projectHash: hash1)
        let key2 = try Keychain.createKey(projectHash: hash2)
        #expect(key1 != key2)
    }

    @Test func createKeyThrowsOnDuplicateHash() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        _ = try Keychain.createKey(projectHash: hash)
        #expect(throws: (any Error).self) {
            try Keychain.createKey(projectHash: hash)
        }
    }

    @Test func getOrCreateKeyDefaultIsNonSyncable() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        _ = try Keychain.getOrCreateKey(projectHash: hash)

        let service = Keychain.serviceName(for: hash)

        // A query restricted to syncable=true must NOT find the item.
        let syncableQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "encryption-key",
            kSecAttrSynchronizable as String: kCFBooleanTrue!,
        ]
        #expect(SecItemCopyMatching(syncableQuery as CFDictionary, nil) == errSecItemNotFound)

        // A query with no syncable restriction must find the item.
        let anyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "encryption-key",
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ]
        #expect(SecItemCopyMatching(anyQuery as CFDictionary, nil) == errSecSuccess)
    }
}

// MARK: - Non-integration tests

@Suite("Keychain.serviceName")
struct KeychainServiceNameTests {
    @Test func formatIsComBioenvPrefixed() {
        let name = Keychain.serviceName(for: "abc1234567890123")
        #expect(name == "com.bioenv.abc1234567890123")
    }

    @Test func hashIsIncludedVerbatim() {
        let hash = "deadbeef01234567"
        #expect(Keychain.serviceName(for: hash).hasSuffix(hash))
    }

    @Test func differentHashesProduceDifferentServiceNames() {
        let a = Keychain.serviceName(for: "aaaaaaaaaaaaaaaa")
        let b = Keychain.serviceName(for: "bbbbbbbbbbbbbbbb")
        #expect(a != b)
    }

    @Test func sameHashProducesSameServiceName() {
        let hash = "1234567890abcdef"
        #expect(Keychain.serviceName(for: hash) == Keychain.serviceName(for: hash))
    }

    @Test func serviceNameMatchesStoreProjectHash() {
        // The service name used for a project must derive from the same hash
        // that Store computes for the same path, so Keychain and Store stay in sync.
        let store = Store(projectPath: "/tmp/test-project")
        let expected = "com.bioenv.\(store.projectHash)"
        #expect(Keychain.serviceName(for: store.projectHash) == expected)
    }
}

@Suite("KeychainError")
struct KeychainErrorTests {
    @Test func descriptionIncludesStatusWhenPresent() {
        let err = KeychainError("retrieval failed", status: -25300)
        #expect(err.description == "retrieval failed (OSStatus: -25300)")
    }

    @Test func descriptionExcludesStatusWhenNil() {
        let err = KeychainError("biometric unavailable")
        #expect(err.description == "biometric unavailable")
    }

    @Test func messageAndStatusAreAccessible() {
        let err = KeychainError("stored key missing", status: errSecItemNotFound)
        #expect(err.message == "stored key missing")
        #expect(err.status == errSecItemNotFound)
    }

    @Test func nilStatusPropertyWhenOmitted() {
        let err = KeychainError("no status")
        #expect(err.status == nil)
    }
}
