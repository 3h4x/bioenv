import Foundation

public enum ConfigError: Error, CustomStringConvertible, Equatable {
    case invalidSyncValue(String)

    public var description: String {
        switch self {
        case .invalidSyncValue(let value):
            return "Invalid sync value '\(value)'. Use one of: on, off, true, false, yes, no."
        }
    }
}

public struct BioenvConfig: Codable, Sendable {
    public var sync: Bool

    public init(sync: Bool) {
        self.sync = sync
    }

    public static let defaultConfig = BioenvConfig(sync: false)

    public static var configPath: String {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(homeDir)/.bioenv/config.json"
    }

    public static func parseSyncValue(_ rawValue: String) throws -> Bool {
        switch rawValue.lowercased() {
        case "on", "true", "yes":
            return true
        case "off", "false", "no":
            return false
        default:
            throw ConfigError.invalidSyncValue(rawValue)
        }
    }

    public static func load(from path: String = BioenvConfig.configPath) -> BioenvConfig {
        guard FileManager.default.fileExists(atPath: path),
              let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let config = try? JSONDecoder().decode(BioenvConfig.self, from: data) else {
            return defaultConfig
        }
        return config
    }

    public func save(to path: String = BioenvConfig.configPath) throws {
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(self)
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
    }
}
