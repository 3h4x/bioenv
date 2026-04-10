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
        // Zero the plaintext buffer as soon as JSON decoding completes so secret
        // bytes don't linger in the heap beyond their point of use.
        var decryptedData = try Crypto.decrypt(data: encryptedData, key: key)
        defer { decryptedData.resetBytes(in: 0..<decryptedData.count) }
        let secrets = try JSONDecoder().decode([String: String].self, from: decryptedData)
        return secrets
    }

    func writeSecrets(_ secrets: [String: String], key: Data) throws {
        try ensureStoreDirectory()
        // Zero the plaintext JSON buffer after encryption so secret bytes don't
        // linger in the heap longer than necessary.
        var jsonData = try JSONEncoder().encode(secrets)
        defer { jsonData.resetBytes(in: 0..<jsonData.count) }
        let encryptedData = try Crypto.encrypt(data: jsonData, key: key)
        let fileURL = URL(fileURLWithPath: storePath)
        try encryptedData.write(to: fileURL)
    }

    /// Returns true if `name` is a valid POSIX environment variable name:
    /// matches `[A-Za-z_][A-Za-z0-9_]*`. Names that fail this check produce
    /// malformed `export` statements when passed to the shell.
    static func isValidEnvVarName(_ name: String) -> Bool {
        guard !name.isEmpty, let first = name.unicodeScalars.first else { return false }
        let leadSet = CharacterSet.letters.union(CharacterSet(charactersIn: "_"))
        let bodySet = leadSet.union(.decimalDigits)
        guard leadSet.contains(first) else { return false }
        return name.unicodeScalars.dropFirst().allSatisfy { bodySet.contains($0) }
    }

    func shellEscape(_ value: String) -> String {
        // Empty string must be quoted so the shell sees an empty argument, not nothing.
        guard !value.isEmpty else { return "''" }
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

            // Strip surrounding quotes (keeps everything inside verbatim, including # characters).
            if value.count >= 2 &&
               ((value.hasPrefix("\"") && value.hasSuffix("\"")) ||
                (value.hasPrefix("'") && value.hasSuffix("'"))) {
                value = String(value.dropFirst().dropLast())
            } else {
                // Unquoted value: strip trailing inline comment (whitespace + #).
                // e.g. KEY=value # my comment  →  value
                if let commentRange = value.range(of: #"\s+#.*$"#, options: .regularExpression) {
                    value = String(value[value.startIndex..<commentRange.lowerBound])
                }
            }

            if isValidEnvVarName(key) {
                result[key] = value
            } else if !key.isEmpty {
                fputs("warning: skipping invalid key '\(key)' (must match [A-Za-z_][A-Za-z0-9_]*)\n", stderr)
            }
        }

        return result
    }
}
