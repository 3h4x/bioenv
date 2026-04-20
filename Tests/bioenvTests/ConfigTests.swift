import Foundation
import Testing
import bioenvLib

@Suite("BioenvConfig")
struct BioenvConfigTests {

    // MARK: - Defaults

    @Test func defaultSyncIsFalse() {
        #expect(BioenvConfig.defaultConfig.sync == false)
    }

    // MARK: - Codable round-trip via JSON

    @Test func decodesFromJSON() throws {
        let json = Data(#"{"sync":true}"#.utf8)
        let config = try JSONDecoder().decode(BioenvConfig.self, from: json)
        #expect(config.sync == true)
    }

    @Test func decodesFromJSONSyncFalse() throws {
        let json = Data(#"{"sync":false}"#.utf8)
        let config = try JSONDecoder().decode(BioenvConfig.self, from: json)
        #expect(config.sync == false)
    }

    @Test func encodingRoundTrip() throws {
        let original = try JSONDecoder().decode(BioenvConfig.self, from: Data(#"{"sync":true}"#.utf8))
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(BioenvConfig.self, from: encoded)
        #expect(decoded.sync == original.sync)
    }

    // MARK: - load() fallback for bad/missing data

    @Test func decodeFailsForBrokenJSON() {
        let broken = Data("not json".utf8)
        let decoded = try? JSONDecoder().decode(BioenvConfig.self, from: broken)
        #expect(decoded == nil)
    }

    @Test func decodeFailsForEmptyData() {
        let decoded = try? JSONDecoder().decode(BioenvConfig.self, from: Data())
        #expect(decoded == nil)
    }

    // MARK: - save / load round-trip via temp file

    @Test func saveAndLoadRoundTrip() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let original = try JSONDecoder().decode(BioenvConfig.self, from: Data(#"{"sync":true}"#.utf8))
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(original)

        let filePath = tempDir.appendingPathComponent("config.json")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        try data.write(to: filePath)

        let loaded = try JSONDecoder().decode(BioenvConfig.self, from: Data(contentsOf: filePath))
        #expect(loaded.sync == true)
    }

    // MARK: - save(to:) / load(from:) injectable path

    private func tempConfigPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("bioenv")
            .appendingPathComponent("config.json")
            .path
    }

    @Test func saveToAndLoadFromRoundTripSyncTrue() throws {
        let path = tempConfigPath()
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let config = BioenvConfig(sync: true)
        try config.save(to: path)
        let loaded = BioenvConfig.load(from: path)
        #expect(loaded.sync == true)
    }

    @Test func saveToAndLoadFromRoundTripSyncFalse() throws {
        let path = tempConfigPath()
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let config = BioenvConfig(sync: false)
        try config.save(to: path)
        let loaded = BioenvConfig.load(from: path)
        #expect(loaded.sync == false)
    }

    @Test func saveCreatesIntermediateDirectories() throws {
        let path = tempConfigPath()
        let dir = (path as NSString).deletingLastPathComponent
        defer { try? FileManager.default.removeItem(atPath: (dir as NSString).deletingLastPathComponent) }
        #expect(!FileManager.default.fileExists(atPath: dir))
        try BioenvConfig(sync: false).save(to: path)
        var isDir: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: dir, isDirectory: &isDir)
        #expect(exists && isDir.boolValue)
    }

    @Test func saveWritesPrettyPrintedJSON() throws {
        let path = tempConfigPath()
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        try BioenvConfig(sync: true).save(to: path)
        let raw = try String(contentsOfFile: path, encoding: .utf8)
        #expect(raw.contains("\n"))
    }

    @Test func loadFromMissingFileReturnsFallback() {
        let path = "/tmp/bioenv_nonexistent_\(UUID().uuidString)/config.json"
        let loaded = BioenvConfig.load(from: path)
        #expect(loaded.sync == BioenvConfig.defaultConfig.sync)
    }

    @Test func loadFromCorruptedFileReturnsFallback() throws {
        let path = tempConfigPath()
        let dir = (path as NSString).deletingLastPathComponent
        defer { try? FileManager.default.removeItem(atPath: (dir as NSString).deletingLastPathComponent) }
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try Data("not valid json {{{".utf8).write(to: URL(fileURLWithPath: path))
        let loaded = BioenvConfig.load(from: path)
        #expect(loaded.sync == BioenvConfig.defaultConfig.sync)
    }

    @Test func loadFromEmptyFileReturnsFallback() throws {
        let path = tempConfigPath()
        let dir = (path as NSString).deletingLastPathComponent
        defer { try? FileManager.default.removeItem(atPath: (dir as NSString).deletingLastPathComponent) }
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try Data().write(to: URL(fileURLWithPath: path))
        let loaded = BioenvConfig.load(from: path)
        #expect(loaded.sync == BioenvConfig.defaultConfig.sync)
    }

    @Test func saveOverwritesPreviousValue() throws {
        let path = tempConfigPath()
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        try BioenvConfig(sync: true).save(to: path)
        try BioenvConfig(sync: false).save(to: path)
        let loaded = BioenvConfig.load(from: path)
        #expect(loaded.sync == false)
    }

    @Test func publicInitMatchesMemberwise() {
        let a = BioenvConfig(sync: true)
        #expect(a.sync == true)
        let b = BioenvConfig(sync: false)
        #expect(b.sync == false)
    }

    @Test func configPathIsInDotBioenvDir() {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser.path
        #expect(BioenvConfig.configPath == "\(homeDir)/.bioenv/config.json")
    }

    @Test func configPathEndsWithConfigJSON() {
        #expect(BioenvConfig.configPath.hasSuffix("/config.json"))
    }

    @Test func loadFromJSONWithUnknownFieldsReturnsDefault() {
        // Codable silently ignores unknown keys — future-proof for added fields.
        let json = Data(#"{"sync":true,"unknownFutureField":"ignored"}"#.utf8)
        let config = try? JSONDecoder().decode(BioenvConfig.self, from: json)
        #expect(config?.sync == true)
    }
}
