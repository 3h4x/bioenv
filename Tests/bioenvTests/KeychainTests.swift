import Foundation
import Testing
import bioenvLib

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
