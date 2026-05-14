import Foundation
import CryptoKit

public struct EnvFileParseError: Error, CustomStringConvertible {
    public let path: String
    public let line: Int
    public let key: String
    public let message: String

    public init(path: String, line: Int, key: String, message: String) {
        self.path = path
        self.line = line
        self.key = key
        self.message = message
    }

    public var description: String {
        "Invalid .env file at \(path):\(line) for key '\(key)': \(message)"
    }
}

public enum StoreError: Error, CustomStringConvertible, Equatable {
    case invalidSecretKey(String)

    public var description: String {
        switch self {
        case .invalidSecretKey(let key):
            return "Encrypted store contains invalid key '\(key)'."
        }
    }
}

public struct Store {
    public let projectPath: String
    public let projectHash: String
    public let storePath: String

    public init(projectPath: String? = nil, storeDir: String? = nil) {
        let path = Self.normalizeProjectPath(projectPath ?? FileManager.default.currentDirectoryPath)
        self.projectPath = path

        let hash = SHA256.hash(data: Data(path.utf8))
        self.projectHash = hash.compactMap { String(format: "%02x", $0) }.joined().prefix(16).description

        let dir = storeDir ?? {
            let homeDir = FileManager.default.homeDirectoryForCurrentUser.path
            return "\(homeDir)/.bioenv"
        }()
        self.storePath = "\(dir)/\(self.projectHash).enc"
    }

    private static func normalizeProjectPath(_ path: String) -> String {
        let expandedPath = (path as NSString).expandingTildeInPath
        if (expandedPath as NSString).isAbsolutePath {
            return (expandedPath as NSString).standardizingPath
        }

        let absolutePath = (FileManager.default.currentDirectoryPath as NSString)
            .appendingPathComponent(expandedPath)
        return (absolutePath as NSString).standardizingPath
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
        try validateSecretKeys(secrets)
        return secrets
    }

    public func writeSecrets(_ secrets: [String: String], key: Data) throws {
        try ensureStoreDirectory()
        try validateSecretKeys(secrets)
        // Zero the plaintext JSON buffer after encryption so secret bytes don't
        // linger in the heap longer than necessary.
        var jsonData = try JSONEncoder().encode(secrets)
        defer { jsonData.resetBytes(in: 0..<jsonData.count) }
        let encryptedData = try Crypto.encrypt(data: jsonData, key: key)
        let fileURL = URL(fileURLWithPath: storePath)
        try encryptedData.write(to: fileURL, options: .atomic)
    }

    // Explicitly ASCII-only — CharacterSet.letters accepts Unicode letters which
    // are not valid in POSIX env var names.
    private static let envVarLeadSet: CharacterSet = {
        let ascii = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
        return ascii.union(CharacterSet(charactersIn: "_"))
    }()
    private static let envVarBodySet: CharacterSet =
        envVarLeadSet.union(CharacterSet(charactersIn: "0123456789"))

    /// Returns true if `name` is a valid POSIX environment variable name:
    /// matches `[A-Za-z_][A-Za-z0-9_]*`. Names that fail this check produce
    /// malformed `export` statements when passed to the shell.
    public static func isValidEnvVarName(_ name: String) -> Bool {
        guard !name.isEmpty, let first = name.unicodeScalars.first else { return false }
        guard envVarLeadSet.contains(first) else { return false }
        return name.unicodeScalars.dropFirst().allSatisfy { envVarBodySet.contains($0) }
    }

    /// Strips at most one trailing newline (`\r\n` or `\n`) from `s`.
    /// This matches the contract for `bioenv set KEY` stdin ingestion: shell pipelines
    /// and `echo` append exactly one newline, which must be removed; embedded newlines
    /// (e.g. PEM keys) must be preserved.
    public static func stripOneTrailingNewline(_ s: String) -> String {
        // Swift treats \r\n as a single grapheme cluster, so dropLast() removes
        // the CRLF pair as one unit — using dropLast(2) would also remove the
        // preceding character.
        if s.hasSuffix("\r\n") { return String(s.dropLast()) }
        if s.hasSuffix("\n") { return String(s.dropLast()) }
        return s
    }

    private func validateSecretKeys(_ secrets: [String: String]) throws {
        for key in secrets.keys where !Self.isValidEnvVarName(key) {
            throw StoreError.invalidSecretKey(key)
        }
    }

    public func shellEscape(_ value: String) -> String {
        // Empty string must be quoted so the shell sees an empty argument, not nothing.
        guard !value.isEmpty else { return "''" }

        // Fast path: all chars are safe to emit unquoted.
        if value.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == "." || $0 == "/" || $0 == ":") }) {
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
        try parseEnvFile(path) { warning in
            fputs(warning, stderr)
        }
    }

    public static func parseEnvFile(
        _ path: String,
        warningHandler: (String) -> Void
    ) throws -> [String: String] {
        var content = try String(contentsOfFile: path, encoding: .utf8)
        // Windows editors commonly prepend a UTF-8 BOM (\u{FEFF}); without stripping it
        // the first key becomes "\u{FEFF}KEY" which fails POSIX validation and is silently skipped.
        if content.hasPrefix("\u{FEFF}") { content = String(content.dropFirst()) }
        content = content.replacingOccurrences(of: "\r\n", with: "\n")
        content = content.replacingOccurrences(of: "\r", with: "\n")
        var result: [String: String] = [:]
        let lines = content.components(separatedBy: "\n")
        var lineIndex = 0

        while lineIndex < lines.count {
            let line = lines[lineIndex]
            var trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") {
                lineIndex += 1
                continue
            }

            // Strip "export " prefix
            if trimmed.hasPrefix("export ") {
                trimmed = String(trimmed.dropFirst(7)).trimmingCharacters(in: .whitespaces)
            }

            guard let equalsIndex = trimmed.firstIndex(of: "=") else {
                lineIndex += 1
                continue
            }

            let key = String(trimmed[trimmed.startIndex..<equalsIndex]).trimmingCharacters(in: .whitespaces)
            let rawValue = String(trimmed[trimmed.index(after: equalsIndex)...])

            if isValidEnvVarName(key) {
                let value = try parseEnvValue(
                    rawValue,
                    path: path,
                    key: key,
                    lineIndex: &lineIndex,
                    lines: lines
                )
                result[key] = value
            } else if !key.isEmpty {
                warningHandler("warning: skipping invalid key '\(key)' (must match [A-Za-z_][A-Za-z0-9_]*)\n")
                skipInvalidValueRecord(
                    rawValue,
                    lineIndex: &lineIndex,
                    lines: lines
                )
            }

            lineIndex += 1
        }

        return result
    }

    private static func parseEnvValue(
        _ rawValue: String,
        path: String,
        key: String,
        lineIndex: inout Int,
        lines: [String]
    ) throws -> String {
        let value = rawValue.trimmingCharacters(in: .whitespaces)
        guard let openingQuote = value.first, openingQuote == "\"" || openingQuote == "'" else {
            return stripInlineComment(from: value)
        }

        if let singleLineValue = extractClosedQuotedValue(from: value, openingQuote: openingQuote) {
            return singleLineValue
        }

        let startLine = lineIndex + 1
        var multilineLines = [String(value.dropFirst())]

        while lineIndex + 1 < lines.count {
            lineIndex += 1
            let continuation = lines[lineIndex]

            if let closingLineValue = extractClosingQuotedLineValue(from: continuation, openingQuote: openingQuote) {
                multilineLines.append(closingLineValue)
                return multilineLines.joined(separator: "\n")
            }

            multilineLines.append(continuation)
        }

        throw EnvFileParseError(
            path: path,
            line: startLine,
            key: key,
            message: "unterminated quoted value"
        )
    }

    private static func skipInvalidValueRecord(
        _ rawValue: String,
        lineIndex: inout Int,
        lines: [String]
    ) {
        let value = rawValue.trimmingCharacters(in: .whitespaces)
        guard let openingQuote = value.first, openingQuote == "\"" || openingQuote == "'" else {
            return
        }

        if extractClosedQuotedValue(from: value, openingQuote: openingQuote) != nil {
            return
        }

        var probeIndex = lineIndex + 1
        while probeIndex < lines.count {
            let continuation = lines[probeIndex]

            if extractClosingQuotedLineValue(from: continuation, openingQuote: openingQuote) != nil {
                lineIndex = probeIndex
                return
            }

            probeIndex += 1
        }

        // If the opening line already contains another quote character, treat it as a
        // malformed single-line record and skip only that physical line. This preserves
        // later valid assignments instead of consuming the rest of the file.
        if value.dropFirst().contains(where: { $0 == "\"" || $0 == "'" }) {
            return
        }

        // No closing quote was found. Consume the rest of the file so lines inside
        // the skipped invalid record are never reparsed as top-level assignments.
        lineIndex = lines.count - 1
    }

    private static func stripInlineComment(from value: String) -> String {
        // Unquoted value: strip trailing inline comment (whitespace + #).
        // e.g. KEY=value # my comment  →  value
        if let commentRange = value.range(of: #"\s+#.*$"#, options: .regularExpression) {
            return String(value[value.startIndex..<commentRange.lowerBound])
        }
        return value
    }

    private static func extractClosedQuotedValue(from value: String, openingQuote: Character) -> String? {
        guard value.first == openingQuote else { return nil }
        let start = value.index(after: value.startIndex)
        guard let closingIndex = lastUnescapedClosingQuoteIndex(
            in: value,
            openingQuote: openingQuote,
            searchStart: start
        ) else { return nil }
        return String(value[start..<closingIndex])
    }

    private static func extractClosingQuotedLineValue(from value: String, openingQuote: Character) -> String? {
        guard let closingIndex = lastMultilineClosingQuoteIndex(
            in: value,
            openingQuote: openingQuote,
            searchStart: value.startIndex
        ) else { return nil }
        return String(value[value.startIndex..<closingIndex])
    }

    private static func hasOnlyTrailingWhitespaceOrComment(_ suffix: Substring) -> Bool {
        guard let firstNonWhitespace = suffix.firstIndex(where: { !$0.isWhitespace }) else {
            return true
        }

        return suffix[firstNonWhitespace] == "#"
    }

    private static func lastUnescapedClosingQuoteIndex(
        in value: String,
        openingQuote: Character,
        searchStart: String.Index
    ) -> String.Index? {
        var candidate: String.Index?
        var index = searchStart

        while index < value.endIndex {
            if value[index] == openingQuote && !isClosingQuoteEscaped(index, in: value, openingQuote: openingQuote) {
                let suffix = value[value.index(after: index)...]
                if hasOnlyTrailingWhitespaceOrComment(suffix) {
                    candidate = index
                }
            }

            index = value.index(after: index)
        }

        return candidate
    }

    private static func lastMultilineClosingQuoteIndex(
        in value: String,
        openingQuote: Character,
        searchStart: String.Index
    ) -> String.Index? {
        var closingIndex: String.Index?
        var unescapedQuoteCount = 0
        var index = searchStart

        while index < value.endIndex {
            if value[index] == openingQuote && !isClosingQuoteEscaped(index, in: value, openingQuote: openingQuote) {
                unescapedQuoteCount += 1
                let suffix = value[value.index(after: index)...]
                if hasOnlyTrailingWhitespaceOrComment(suffix) {
                    closingIndex = index
                }
            }

            index = value.index(after: index)
        }

        guard unescapedQuoteCount == 1 else { return nil }
        return closingIndex
    }

    private static func isClosingQuoteEscaped(
        _ index: String.Index,
        in value: String,
        openingQuote: Character
    ) -> Bool {
        guard openingQuote == "\"" else { return false }

        var backslashCount = 0
        var probe = index

        while probe > value.startIndex {
            let previous = value.index(before: probe)
            guard value[previous] == "\\" else { break }
            backslashCount += 1
            probe = previous
        }

        return backslashCount.isMultiple(of: 2) == false
    }

}
