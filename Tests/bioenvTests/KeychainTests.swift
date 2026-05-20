import Foundation
import Security
import Testing
@testable import bioenvLib

private final class MockKeychainSecurityBackend: @unchecked Sendable {
    struct Entry {
        let data: Data
        let syncable: Bool
        let accessible: String
    }

    var entries: [String: Entry] = [:]
    var randomKeys: [Data]
    var lastCopyMatchingQuery: [String: Any]?
    var lastAddQuery: [String: Any]?
    var lastDeleteQuery: [String: Any]?
    var forcedCopyMatchingResult: (([String: Any]) -> (OSStatus, AnyObject?))?
    var forcedAddStatus: OSStatus?
    var forcedDeleteStatus: OSStatus?
    var forcedRandomStatus: OSStatus?

    init(randomKeys: [Data] = [Data((0..<32).map(UInt8.init))]) {
        self.randomKeys = randomKeys
    }

    func client() -> Keychain.SecurityClient {
        Keychain.SecurityClient(
            copyMatching: { [self] query in
                copyMatching(query: query)
            },
            add: { [self] query in
                add(query: query)
            },
            delete: { [self] query in
                delete(query: query)
            },
            randomCopyBytes: { [self] buffer in
                randomCopyBytes(buffer: buffer)
            }
        )
    }

    private func identifier(for query: [String: Any]) -> String? {
        guard
            let service = query[kSecAttrService as String] as? String,
            let account = query[kSecAttrAccount as String] as? String
        else {
            return nil
        }
        return "\(service)\u{0}\(account)"
    }

    private func syncableFilter(from query: [String: Any]) -> Bool? {
        let key = kSecAttrSynchronizable as String
        guard let value = query[key] else { return nil }
        if let syncable = value as? Bool {
            return syncable
        }
        if let syncable = value as? String, syncable == (kSecAttrSynchronizableAny as String) {
            return nil
        }
        return nil
    }

    private func copyMatching(query: [String: Any]) -> (OSStatus, AnyObject?) {
        lastCopyMatchingQuery = query

        if let forcedCopyMatchingResult {
            return forcedCopyMatchingResult(query)
        }

        guard let identifier = identifier(for: query) else {
            return (errSecParam, nil)
        }
        guard let entry = entries[identifier] else {
            return (errSecItemNotFound, nil)
        }

        if let syncableFilter = syncableFilter(from: query), syncableFilter != entry.syncable {
            return (errSecItemNotFound, nil)
        }

        if query[kSecReturnData as String] as? Bool == true {
            return (errSecSuccess, entry.data as AnyObject)
        }
        if query[kSecReturnAttributes as String] as? Bool == true {
            return (errSecSuccess, [
                kSecAttrService as String: query[kSecAttrService as String] as Any,
                kSecAttrAccount as String: query[kSecAttrAccount as String] as Any,
                kSecAttrSynchronizable as String: entry.syncable,
                kSecAttrAccessible as String: entry.accessible,
            ] as NSDictionary)
        }
        return (errSecSuccess, nil)
    }

    private func add(query: [String: Any]) -> OSStatus {
        lastAddQuery = query

        if let forcedAddStatus {
            return forcedAddStatus
        }

        guard
            let identifier = identifier(for: query),
            let data = query[kSecValueData as String] as? Data
        else {
            return errSecParam
        }

        if entries[identifier] != nil {
            return errSecDuplicateItem
        }

        let syncable = query[kSecAttrSynchronizable as String] as? Bool ?? false
        let accessible = query[kSecAttrAccessible as String] as? String ?? ""
        entries[identifier] = Entry(data: data, syncable: syncable, accessible: accessible)
        return errSecSuccess
    }

    private func delete(query: [String: Any]) -> OSStatus {
        lastDeleteQuery = query

        if let forcedDeleteStatus {
            return forcedDeleteStatus
        }

        guard let identifier = identifier(for: query) else {
            return errSecParam
        }

        return entries.removeValue(forKey: identifier) == nil ? errSecItemNotFound : errSecSuccess
    }

    private func randomCopyBytes(buffer: UnsafeMutableRawBufferPointer) -> OSStatus {
        if let forcedRandomStatus {
            return forcedRandomStatus
        }
        guard let nextKey = randomKeys.isEmpty ? nil : randomKeys.removeFirst() else {
            return errSecAllocate
        }
        guard nextKey.count == buffer.count else {
            return errSecParam
        }
        nextKey.withUnsafeBytes { source in
            buffer.copyMemory(from: source)
        }
        return errSecSuccess
    }
}

private func withMockKeychain<T>(
    randomKeys: [Data] = [Data((0..<32).map(UInt8.init))],
    body: (MockKeychainSecurityBackend) throws -> T
) rethrows -> T {
    let backend = MockKeychainSecurityBackend(randomKeys: randomKeys)
    return try Keychain.withSecurityClient(backend.client()) {
        try body(backend)
    }
}

private func uniqueKeychainTestHash() -> String {
    String(UUID().uuidString.lowercased().filter { $0.isHexDigit }.prefix(16))
}

private func deleteDirectKeychainItem(projectHash: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: Keychain.serviceName(for: projectHash),
        kSecAttrAccount as String: "encryption-key",
        kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    ]
    SecItemDelete(query as CFDictionary)
}

private func canUseDirectKeychainItem(syncable: Bool) -> Bool {
    let hash = uniqueKeychainTestHash()
    defer { deleteDirectKeychainItem(projectHash: hash) }

    let accessibility = syncable
        ? kSecAttrAccessibleWhenUnlocked
        : kSecAttrAccessibleWhenUnlockedThisDeviceOnly

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: Keychain.serviceName(for: hash),
        kSecAttrAccount as String: "encryption-key",
        kSecValueData as String: Data(repeating: 0, count: 32),
        kSecAttrAccessible as String: accessibility,
        kSecAttrSynchronizable as String: syncable,
    ]
    return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
}

private let keychainIntegrationOptInVariable = "BIOENV_RUN_KEYCHAIN_INTEGRATION_TESTS"

private func isKeychainIntegrationEnabled(environment: [String: String]) -> Bool {
    guard let rawValue = environment[keychainIntegrationOptInVariable] else {
        return false
    }

    switch rawValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
    case "1", "true", "yes", "on":
        return true
    default:
        return false
    }
}

private let keychainIntegrationRequested =
    isKeychainIntegrationEnabled(environment: ProcessInfo.processInfo.environment)

private let keychainIntegrationAvailable: Bool = {
    guard keychainIntegrationRequested else { return false }
    return canUseDirectKeychainItem(syncable: false)
}()

private let keychainSyncableIntegrationAvailable: Bool = {
    guard keychainIntegrationAvailable else { return false }
    return canUseDirectKeychainItem(syncable: true)
}()

// MARK: - Integration tests (require a macOS Keychain; no Touch ID needed)

/// These tests call SecItem* APIs directly on the macOS Keychain.
/// They do NOT require Touch ID — only an unlocked Keychain (standard on any interactive Mac session).
/// They are opt-in so normal `swift test` runs stay off the real login Keychain.
/// Each test generates a unique project hash so it never conflicts with real bioenv entries.
@Suite("Keychain.CRUD", .serialized)
struct KeychainCRUDTests {
    private func uniqueHash() -> String {
        uniqueKeychainTestHash()
    }

    private func attributes(for hash: String, syncable: Any = kSecAttrSynchronizableAny) throws -> [String: Any]? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Keychain.serviceName(for: hash),
            kSecAttrAccount as String: "encryption-key",
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: syncable,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        #expect(status == errSecSuccess)
        return result as? [String: Any]
    }

    @Test(.enabled(if: keychainIntegrationAvailable)) func createKeyReturns32Bytes() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        let key = try Keychain.createKey(projectHash: hash)
        #expect(key.count == 32)
    }

    @Test(.enabled(if: keychainIntegrationAvailable)) func getKeyRetrievesSameKeyAsCreated() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        let created = try Keychain.createKey(projectHash: hash)
        let retrieved = try Keychain.getKey(projectHash: hash)
        #expect(created == retrieved)
    }

    @Test(.enabled(if: keychainIntegrationAvailable)) func getKeyThrowsKeyNotFoundError() {
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

    @Test(.enabled(if: keychainIntegrationAvailable)) func deleteKeyRemovesExistingKey() throws {
        let hash = uniqueHash()
        _ = try Keychain.createKey(projectHash: hash)
        try Keychain.deleteKey(projectHash: hash)
        #expect(throws: (any Error).self) {
            try Keychain.getKey(projectHash: hash)
        }
    }

    @Test(.enabled(if: keychainIntegrationAvailable)) func deleteKeyIsIdempotentForMissingKey() {
        let hash = uniqueHash()
        #expect(throws: Never.self) {
            try Keychain.deleteKey(projectHash: hash)
        }
    }

    @Test(.enabled(if: keychainIntegrationAvailable)) func getOrCreateKeyCreatesKeyWhenMissing() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        let key = try Keychain.getOrCreateKey(projectHash: hash)
        #expect(key.count == 32)
    }

    @Test(.enabled(if: keychainIntegrationAvailable)) func getOrCreateKeyReturnsSameKeyOnSubsequentCalls() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        let first = try Keychain.getOrCreateKey(projectHash: hash)
        let second = try Keychain.getOrCreateKey(projectHash: hash)
        #expect(first == second)
    }

    @Test(.enabled(if: keychainIntegrationAvailable)) func hasKeyReturnsFalseWhenMissing() throws {
        let hash = uniqueHash()
        #expect(try Keychain.hasKey(projectHash: hash) == false)
    }

    @Test(.enabled(if: keychainIntegrationAvailable)) func hasKeyReturnsTrueAfterCreate() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        _ = try Keychain.createKey(projectHash: hash)
        #expect(try Keychain.hasKey(projectHash: hash))
    }

    @Test(.enabled(if: keychainIntegrationAvailable)) func createdKeysAreRandom() throws {
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

    @Test(.enabled(if: keychainIntegrationAvailable)) func createKeyThrowsOnDuplicateHash() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        _ = try Keychain.createKey(projectHash: hash)
        #expect(throws: (any Error).self) {
            try Keychain.createKey(projectHash: hash)
        }
    }

    @Test(.enabled(if: keychainIntegrationAvailable)) func getOrCreateKeyDefaultIsNonSyncable() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        _ = try Keychain.getOrCreateKey(projectHash: hash)

        #expect(try attributes(for: hash, syncable: true) == nil)

        let attrs = try #require(try attributes(for: hash, syncable: false))
        if let syncable = attrs[kSecAttrSynchronizable as String] as? Bool {
            #expect(syncable == false)
        }
        if let accessible = attrs[kSecAttrAccessible as String] as? String {
            #expect(accessible == (kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String))
        }
    }

    @Test(.enabled(if: keychainSyncableIntegrationAvailable)) func createKeySyncableTrueUsesWhenUnlockedAccessibility() throws {
        let hash = uniqueHash()
        defer { try? Keychain.deleteKey(projectHash: hash) }
        _ = try Keychain.createKey(projectHash: hash, syncable: true)

        let attrs = try #require(try attributes(for: hash, syncable: true))
        #expect(attrs[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(attrs[kSecAttrAccessible as String] as? String == (kSecAttrAccessibleWhenUnlocked as String))
    }

    @Test func mockBackendUsesSyncableTrueAccessibility() throws {
        try withMockKeychain { backend in
            let hash = uniqueHash()
            _ = try Keychain.createKey(projectHash: hash, syncable: true)

            let service = Keychain.serviceName(for: hash)
            let identifier = "\(service)\u{0}encryption-key"
            let entry = try #require(backend.entries[identifier])
            #expect(entry.syncable)
            #expect(entry.accessible == (kSecAttrAccessibleWhenUnlocked as String))
        }
    }

    @Test func mockBackendGetOrCreateDefaultUsesNonSyncableThisDeviceOnlyAccessibility() throws {
        try withMockKeychain { backend in
            _ = try Keychain.getOrCreateKey(projectHash: uniqueHash())

            let addQuery = try #require(backend.lastAddQuery)
            #expect(addQuery[kSecAttrSynchronizable as String] as? Bool == false)
            #expect(addQuery[kSecAttrAccessible as String] as? String == (kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String))
        }
    }

    @Test func mockBackendGetKeyThrowsWhenKeychainReturnsUnexpectedDataType() {
        withMockKeychain { backend in
            backend.forcedCopyMatchingResult = { _ in
                (errSecSuccess, "not-data" as NSString)
            }

            #expect(throws: KeychainError.self) {
                try Keychain.getKey(projectHash: uniqueHash())
            }
        }
    }

    @Test func mockBackendCreateKeyPropagatesRandomGenerationFailure() {
        withMockKeychain { backend in
            backend.forcedRandomStatus = errSecAllocate

            do {
                _ = try Keychain.createKey(projectHash: uniqueHash())
                Issue.record("Expected KeychainError to be thrown")
            } catch let error as KeychainError {
                #expect(error.status == errSecAllocate)
            } catch {
                Issue.record("Expected KeychainError, got \(error)")
            }
        }
    }
}

// MARK: - Non-integration tests

@Suite("Keychain integration opt-in")
struct KeychainIntegrationOptInTests {
    @Test func missingVariableDisablesIntegration() {
        #expect(isKeychainIntegrationEnabled(environment: [:]) == false)
    }

    @Test func truthyValuesEnableIntegration() {
        let truthyValues = ["1", "true", "TRUE", " yes ", "On"]

        for value in truthyValues {
            #expect(
                isKeychainIntegrationEnabled(
                    environment: [keychainIntegrationOptInVariable: value]
                )
            )
        }
    }

    @Test func falseyAndUnknownValuesKeepIntegrationDisabled() {
        let falseyValues = ["0", "false", "off", "no", "", "maybe"]

        for value in falseyValues {
            #expect(
                isKeychainIntegrationEnabled(
                    environment: [keychainIntegrationOptInVariable: value]
                ) == false
            )
        }
    }
}

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
