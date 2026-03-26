import Foundation
import CryptoKit

struct Store {
    let projectPath: String
    let projectHash: String
    let storePath: String

    init(projectPath: String? = nil) {
        let path = projectPath ?? FileManager.default.currentDirectoryPath
        self.projectPath = path

        let hash = SHA256.hash(data: Data(path.utf8))
        self.projectHash = hash.compactMap { String(format: "%02x", $0) }.joined().prefix(16).description

        let homeDir = FileManager.default.homeDirectoryForCurrentUser.path
        self.storePath = "\(homeDir)/.bioenv/\(self.projectHash).enc"
    }

    func ensureStoreDirectory() throws {
        let dir = (storePath as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    }

    func readSecrets(key: Data) throws -> [String: String] {
        let fileURL = URL(fileURLWithPath: storePath)

        guard FileManager.default.fileExists(atPath: storePath) else {
            return [:]
        }

        let encryptedData = try Data(contentsOf: fileURL)
        let decryptedData = try Crypto.decrypt(data: encryptedData, key: key)
        let secrets = try JSONDecoder().decode([String: String].self, from: decryptedData)
        return secrets
    }

    func writeSecrets(_ secrets: [String: String], key: Data) throws {
        try ensureStoreDirectory()
        let jsonData = try JSONEncoder().encode(secrets)
        let encryptedData = try Crypto.encrypt(data: jsonData, key: key)
        let fileURL = URL(fileURLWithPath: storePath)
        try encryptedData.write(to: fileURL)
    }

    func shellEscape(_ value: String) -> String {
        if value.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == "." || $0 == "/" || $0 == ":" }) {
            return value
        }
        let escaped = value.replacingOccurrences(of: "'", with: "'\"'\"'")
        return "'\(escaped)'"
    }

    static func parseEnvFile(_ path: String) throws -> [String: String] {
        let content = try String(contentsOfFile: path, encoding: .utf8)
        var result: [String: String] = [:]

        for line in content.components(separatedBy: .newlines) {
            var trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            // Strip "export " prefix
            if trimmed.hasPrefix("export ") {
                trimmed = String(trimmed.dropFirst(7)).trimmingCharacters(in: .whitespaces)
            }

            guard let equalsIndex = trimmed.firstIndex(of: "=") else { continue }

            let key = String(trimmed[trimmed.startIndex..<equalsIndex]).trimmingCharacters(in: .whitespaces)
            var value = String(trimmed[trimmed.index(after: equalsIndex)...]).trimmingCharacters(in: .whitespaces)

            // Strip surrounding quotes
            if (value.hasPrefix("\"") && value.hasSuffix("\"")) ||
               (value.hasPrefix("'") && value.hasSuffix("'")) {
                value = String(value.dropFirst().dropLast())
            }

            if !key.isEmpty {
                result[key] = value
            }
        }

        return result
    }
}
