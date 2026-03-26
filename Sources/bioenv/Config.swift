import Foundation

struct BioenvConfig: Codable {
    var sync: Bool

    static let defaultConfig = BioenvConfig(sync: false)

    static var configPath: String {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(homeDir)/.bioenv/config.json"
    }

    static func load() -> BioenvConfig {
        guard FileManager.default.fileExists(atPath: configPath),
              let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
              let config = try? JSONDecoder().decode(BioenvConfig.self, from: data) else {
            return defaultConfig
        }
        return config
    }

    func save() throws {
        let dir = (BioenvConfig.configPath as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(self)
        try data.write(to: URL(fileURLWithPath: BioenvConfig.configPath))
    }
}
