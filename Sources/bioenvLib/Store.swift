import Foundation
import CryptoKit

public struct Store {
    public let projectPath: String
    public let projectHash: String
    public let storePath: String

    public init(projectPath: String? = nil, storeDir: String? = nil) {
        let path = projectPath ?? FileManager.default.currentDirectoryPath
        self.projectPath = path

        let hash = SHA256.hash(data: Data(path.utf8))
        self.projectHash = hash.compactMap { String(format: "%02x", $0) }.joined().prefix(16).description

        let dir = storeDir ?? {
            let homeDir = FileManager.default.homeDirectoryForCurrentUser.path
            return "\(homeDir)/.bioenv"
        }()
        self.storePath = "\(dir)/\(self.projectHash).enc"
    }

    public func ensureStoreDirectory() throws {
        let dir = (storePath as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    }

    public func readSecrets(key: Data) throws -> [String: String] {
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

    public func writeSecrets(_ secrets: [String: String], key: Data) throws {
        try ensureStoreDirectory()
        // Zero the plaintext JSON buffer after encryption so secret bytes don't
        // linger in the heap longer than necessary.
        var jsonData = try JSONEncoder().encode(secrets)
        defer { jsonData.resetBytes(in: 0..<jsonData.count) }
        let encryptedData = try Crypto.encrypt(data: jsonData, key: key)
        let fileURL = URL(fileURLWithPath: storePath)
        try encryptedData.write(to: fileURL, options: .atomic)
    }

    /// Returns true if `name` is a valid POSIX environment variable name:
    /// matches `[A-Za-z_][A-Za-z0-9_]*`. Names that fail this check produce
    /// malformed `export` statements when passed to the shell.
    public static func isValidEnvVarName(_ name: String) -> Bool {
        guard !name.isEmpty, let first = name.unicodeScalars.first else { return false }
        // Explicitly ASCII-only — CharacterSet.letters accepts Unicode letters which
        // are not valid in POSIX env var names.
        let asciiLetters = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
        let leadSet = asciiLetters.union(CharacterSet(charactersIn: "_"))
        let bodySet = leadSet.union(CharacterSet(charactersIn: "0123456789"))
        guard leadSet.contains(first) else { return false }
        return name.unicodeScalars.dropFirst().allSatisfy { bodySet.contains($0) }
    }

    public func shellEscape(_ value: String) -> String {
        // Empty string must be quoted so the shell sees an empty argument, not nothing.
        guard !value.isEmpty else { return "''" }

        // Fast path: all chars are safe to emit unquoted.
        if value.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == "." || $0 == "/" || $0 == ":" }) {
            return value
        }

        // If the value contains control characters (newlines, tabs, etc.), a regular
        // single-quoted string would emit a literal newline into the eval stream, which
        // breaks the shell.  Use ANSI-C $'...' quoting instead — supported by bash and
        // zsh (the only shells targeted via direnv).
        let hasControlChars = value.unicodeScalars.contains { $0.value < 32 || $0.value == 127 }
        if hasControlChars {
            var escaped = ""
            for scalar in value.unicodeScalars {
                switch scalar.value {
                case 0x0A: escaped += "\\n"
                case 0x0D: escaped += "\\r"
                case 0x09: escaped += "\\t"
                case 0x5C: escaped += "\\\\"   // backslash → \\
                case 0x27: escaped += "\\'"    // single quote → \'
                case 0..<32, 127:
                    escaped += String(format: "\\x%02x", scalar.value)
                default:
                    escaped += String(scalar)
                }
            }
            return "$'\(escaped)'"
        }

        // Standard single-quote escaping for values with printable special chars.
        // A single quote inside is broken out of the single-quoted string, emitted
        // as a double-quoted literal ', then the single-quoted string resumes.
        let escaped = value.replacingOccurrences(of: "'", with: "'\"'\"'")
        return "'\(escaped)'"
    }

    public static func parseEnvFile(_ path: String) throws -> [String: String] {
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
