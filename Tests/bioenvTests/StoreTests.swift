import Foundation
import CryptoKit
import Testing
import bioenvLib

@Suite("Store.shellEscape")
struct ShellEscapeTests {
    let store = Store(projectPath: "/tmp/test", storeDir: "/tmp")

    // MARK: - Unquoted (safe chars)

    @Test func safeAlphanumeric() {
        #expect(store.shellEscape("hello123") == "hello123")
    }

    @Test func safePunctuation() {
        #expect(store.shellEscape("path/to/file.txt") == "path/to/file.txt")
        #expect(store.shellEscape("host:8080") == "host:8080")
        #expect(store.shellEscape("kebab-case") == "kebab-case")
        #expect(store.shellEscape("under_score") == "under_score")
    }

    // MARK: - Single-quoted (printable special chars)

    @Test func emptyString() {
        #expect(store.shellEscape("") == "''")
    }

    @Test func valueWithSpaces() {
        #expect(store.shellEscape("hello world") == "'hello world'")
    }

    @Test func valueWithDollarSign() {
        #expect(store.shellEscape("$SECRET") == "'$SECRET'")
    }

    @Test func valueWithSingleQuote() {
        // it's → 'it'"'"'s'
        #expect(store.shellEscape("it's") == "'it'\"'\"'s'")
    }

    @Test func valueWithDoubleQuote() {
        #expect(store.shellEscape("say \"hi\"") == "'say \"hi\"'")
    }

    // MARK: - ANSI-C $'...' quoting (control characters)

    @Test func newline() {
        #expect(store.shellEscape("line1\nline2") == "$'line1\\nline2'")
    }

    @Test func carriageReturn() {
        #expect(store.shellEscape("foo\rbar") == "$'foo\\rbar'")
    }

    @Test func tab() {
        #expect(store.shellEscape("col1\tcol2") == "$'col1\\tcol2'")
    }

    @Test func backslashWithControlChar() {
        // Backslash must be escaped as \\ inside $'...' when combined with a control char.
        #expect(store.shellEscape("a\\\nb") == "$'a\\\\\\nb'")
    }

    @Test func singleQuoteInControlCharValue() {
        // A single quote inside a value that also has a newline goes through $'...' path.
        #expect(store.shellEscape("it's\nalive") == "$'it\\'s\\nalive'")
    }

    @Test func nullByte() {
        #expect(store.shellEscape("a\0b") == "$'a\\x00b'")
    }

    @Test func del() {
        let del = String(UnicodeScalar(127)!)
        #expect(store.shellEscape("a\(del)b") == "$'a\\x7fb'")
    }

    @Test func mixedControlAndPrintable() {
        // Printable chars after a newline should pass through unescaped.
        #expect(store.shellEscape("key\nvalue=1") == "$'key\\nvalue=1'")
    }

    // MARK: - Backslash (printable, not a control char)

    @Test func backslashStandaloneIsSingleQuoted() {
        // 0x5C is not a control char so the single-quote path runs, not $'...'.
        // One backslash wrapped in single quotes: '\'.
        #expect(store.shellEscape("\\") == "'\\'")
    }

    @Test func backslashWithControlCharIsAnsiC() {
        // When the value also contains a newline, the $'...' path fires and
        // the backslash is doubled to \\ inside $'...'.
        #expect(store.shellEscape("\\\n") == "$'\\\\\\n'")
    }

    // MARK: - Unicode / non-ASCII printable chars

    @Test func emojiIsSingleQuoted() {
        // Emoji are not in the alphanumeric/punctuation safe set, so they are
        // single-quoted. They are not control chars, so single-quote path applies.
        #expect(store.shellEscape("🔑") == "'🔑'")
    }

    @Test func atSignIsSingleQuoted() {
        #expect(store.shellEscape("user@example.com") == "'user@example.com'")
    }

    @Test func pipeCharIsSingleQuoted() {
        #expect(store.shellEscape("a|b") == "'a|b'")
    }

    @Test func exclamationMarkIsSingleQuoted() {
        #expect(store.shellEscape("hello!") == "'hello!'")
    }

    // MARK: - Safe fast path

    @Test func valueWithOnlyLettersAndNumbers() {
        // All alphanum → fast path, no quoting.
        #expect(store.shellEscape("ABCDEFabcdef0123456789") == "ABCDEFabcdef0123456789")
    }

    @Test func valueWithAllSafePunctuation() {
        #expect(store.shellEscape("a_b-c.d/e:f") == "a_b-c.d/e:f")
    }
}

@Suite("Store.isValidEnvVarName")
struct EnvVarNameTests {
    @Test func validNames() {
        #expect(Store.isValidEnvVarName("FOO"))
        #expect(Store.isValidEnvVarName("_BAR"))
        #expect(Store.isValidEnvVarName("foo_bar_123"))
    }

    @Test func invalidNames() {
        #expect(!Store.isValidEnvVarName(""))
        #expect(!Store.isValidEnvVarName("1INVALID"))
        #expect(!Store.isValidEnvVarName("HAS-DASH"))
        #expect(!Store.isValidEnvVarName("HAS SPACE"))
    }

    @Test func unicodeLettersRejected() {
        // CharacterSet.letters accepts é, ñ, etc. — POSIX names must be ASCII only.
        #expect(!Store.isValidEnvVarName("café"))
        #expect(!Store.isValidEnvVarName("naïve"))
        #expect(!Store.isValidEnvVarName("日本語"))
        #expect(!Store.isValidEnvVarName("_válid_looking"))
    }

    @Test func singleUnderscore() {
        #expect(Store.isValidEnvVarName("_"))
    }

    @Test func allDigitsRejected() {
        #expect(!Store.isValidEnvVarName("123"))
    }
}

@Suite("Store.parseEnvFile")
struct ParseEnvFileTests {
    /// Write `content` to a temp file, parse it, return the result.
    private func parse(_ content: String) throws -> [String: String] {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString + ".env")
        defer { try? FileManager.default.removeItem(at: url) }
        try content.write(to: url, atomically: true, encoding: .utf8)
        return try Store.parseEnvFile(url.path)
    }

    // MARK: - Basic parsing

    @Test func basicKeyValue() throws {
        let result = try parse("FOO=bar\n")
        #expect(result["FOO"] == "bar")
    }

    @Test func multipleKeys() throws {
        let result = try parse("A=1\nB=2\nC=3\n")
        #expect(result["A"] == "1")
        #expect(result["B"] == "2")
        #expect(result["C"] == "3")
    }

    @Test func emptyFile() throws {
        let result = try parse("")
        #expect(result.isEmpty)
    }

    @Test func emptyValue() throws {
        let result = try parse("KEY=\n")
        #expect(result["KEY"] == "")
    }

    // MARK: - Comments and blank lines

    @Test func commentsSkipped() throws {
        let result = try parse("# this is a comment\nFOO=bar\n")
        #expect(result.count == 1)
        #expect(result["FOO"] == "bar")
    }

    @Test func blankLinesSkipped() throws {
        let result = try parse("\n\nFOO=bar\n\n")
        #expect(result.count == 1)
        #expect(result["FOO"] == "bar")
    }

    @Test func inlineCommentStrippedFromUnquotedValue() throws {
        let result = try parse("KEY=value # my comment\n")
        #expect(result["KEY"] == "value")
    }

    @Test func inlineCommentWithNoSpaceIsNotStripped() throws {
        // "#" with no leading whitespace is NOT treated as a comment separator.
        let result = try parse("KEY=value#notacomment\n")
        #expect(result["KEY"] == "value#notacomment")
    }

    // MARK: - export prefix

    @Test func exportPrefixStripped() throws {
        let result = try parse("export FOO=bar\n")
        #expect(result["FOO"] == "bar")
    }

    @Test func exportPrefixWithSpacesStripped() throws {
        let result = try parse("export   FOO=bar\n")
        #expect(result["FOO"] == "bar")
    }

    // MARK: - Quoted values

    @Test func singleQuotedValue() throws {
        let result = try parse("KEY='hello world'\n")
        #expect(result["KEY"] == "hello world")
    }

    @Test func doubleQuotedValue() throws {
        let result = try parse("KEY=\"hello world\"\n")
        #expect(result["KEY"] == "hello world")
    }

    @Test func singleQuotedValuePreservesHash() throws {
        // A # inside quotes is NOT treated as a comment.
        let result = try parse("KEY='value # not a comment'\n")
        #expect(result["KEY"] == "value # not a comment")
    }

    @Test func doubleQuotedValuePreservesHash() throws {
        let result = try parse("KEY=\"value # not a comment\"\n")
        #expect(result["KEY"] == "value # not a comment")
    }

    @Test func emptyDoubleQuotedValue() throws {
        let result = try parse("KEY=\"\"\n")
        #expect(result["KEY"] == "")
    }

    @Test func emptySingleQuotedValue() throws {
        let result = try parse("KEY=''\n")
        #expect(result["KEY"] == "")
    }

    // MARK: - Values containing equals signs

    @Test func unquotedValueWithEqualsSign() throws {
        // Only the FIRST '=' splits key from value.
        let result = try parse("KEY=a=b=c\n")
        #expect(result["KEY"] == "a=b=c")
    }

    @Test func quotedValueWithEqualsSign() throws {
        let result = try parse("KEY=\"a=b=c\"\n")
        #expect(result["KEY"] == "a=b=c")
    }

    // MARK: - Invalid / skipped keys

    @Test func invalidKeySkipped() throws {
        let result = try parse("1INVALID=value\nVALID=ok\n")
        #expect(result["1INVALID"] == nil)
        #expect(result["VALID"] == "ok")
    }

    @Test func keyWithDashSkipped() throws {
        let result = try parse("HAS-DASH=value\nFOO=bar\n")
        #expect(result["HAS-DASH"] == nil)
        #expect(result["FOO"] == "bar")
    }

    @Test func lineWithoutEqualSignSkipped() throws {
        let result = try parse("NODIVIDER\nFOO=bar\n")
        #expect(result.count == 1)
        #expect(result["FOO"] == "bar")
    }

    @Test func crlfLineEndings() throws {
        let result = try parse("A=1\r\nB=2\r\nC=3\r\n")
        #expect(result["A"] == "1")
        #expect(result["B"] == "2")
        #expect(result["C"] == "3")
    }

    @Test func nonexistentFileThrows() {
        #expect(throws: (any Error).self) {
            try Store.parseEnvFile("/nonexistent/path/that/does/not/exist.env")
        }
    }

    @Test func spacesAroundEquals() throws {
        // Many .env generators emit `KEY = value`; both sides should be trimmed.
        let result = try parse("KEY = value\n")
        #expect(result["KEY"] == "value")
    }

    @Test func mismatchedQuotesKeptVerbatim() throws {
        // Single-open / double-close is not a quoted value; treat as unquoted literal.
        let result = try parse("KEY='mismatch\"\n")
        #expect(result["KEY"] == "'mismatch\"")
    }

    @Test func unquotedHashOnlyValue() throws {
        // A bare `#` with no leading whitespace is the entire value, not a comment.
        let result = try parse("KEY=#\n")
        #expect(result["KEY"] == "#")
    }

    @Test func unicodeKeySkipped() throws {
        // Keys with non-ASCII letters are invalid POSIX names and must be skipped.
        let result = try parse("café=value\nVALID=ok\n")
        #expect(result["café"] == nil)
        #expect(result["VALID"] == "ok")
    }

    @Test func singleCharKey() throws {
        let result = try parse("A=1\n")
        #expect(result["A"] == "1")
    }

    // MARK: - export prefix edge cases

    @Test func exportKeywordWithoutSpaceIsNotStripped() throws {
        // "export" requires a trailing space; "exportFOO=bar" has key "exportFOO".
        let result = try parse("exportFOO=bar\nVALID=ok\n")
        #expect(result["exportFOO"] == "bar")
        #expect(result["VALID"] == "ok")
    }

    @Test func bareExportKeywordLineSkipped() throws {
        // "export" alone has no "=" so the line is skipped.
        let result = try parse("export\nFOO=bar\n")
        #expect(result.count == 1)
        #expect(result["FOO"] == "bar")
    }

    // MARK: - Whitespace handling

    @Test func leadingWhitespaceInLineIsTrimmed() throws {
        let result = try parse("   KEY=value\n")
        #expect(result["KEY"] == "value")
    }

    @Test func multipleSpacesBeforeInlineCommentStripped() throws {
        let result = try parse("KEY=value   # comment\n")
        #expect(result["KEY"] == "value")
    }

    // MARK: - Value-starting-with-hash (documents current behavior)

    @Test func valueStartingWithHashNotTreatedAsComment() throws {
        // After trimming whitespace from the raw value, "#comment" starts with "#".
        // The inline-comment regex requires leading whitespace (\s+#), so no match.
        let result = try parse("KEY= # comment\n")
        #expect(result["KEY"] == "# comment")
    }

    // MARK: - Long / unusual values

    @Test func veryLongUnquotedValue() throws {
        let long = String(repeating: "x", count: 4096)
        let result = try parse("KEY=\(long)\n")
        #expect(result["KEY"] == long)
    }

    @Test func veryLongQuotedValue() throws {
        let long = String(repeating: "y", count: 4096)
        let result = try parse("KEY=\"\(long)\"\n")
        #expect(result["KEY"] == long)
    }

    @Test func valueWithEqualsInsideDoubleQuotes() throws {
        let result = try parse("KEY=\"a=b=c=d\"\n")
        #expect(result["KEY"] == "a=b=c=d")
    }
}

@Suite("Store.projectHash")
struct ProjectHashTests {
    @Test func hashIsSixteenHexChars() {
        let store = Store(projectPath: "/some/project/path")
        #expect(store.projectHash.count == 16)
        #expect(store.projectHash.allSatisfy { $0.isHexDigit })
    }

    @Test func samePathProducesSameHash() {
        let a = Store(projectPath: "/home/user/project")
        let b = Store(projectPath: "/home/user/project")
        #expect(a.projectHash == b.projectHash)
    }

    @Test func differentPathsProduceDifferentHashes() {
        let a = Store(projectPath: "/home/user/alpha")
        let b = Store(projectPath: "/home/user/beta")
        #expect(a.projectHash != b.projectHash)
    }

    @Test func knownPathProducesExpectedHash() {
        // SHA-256("/tmp/test")[0..<16 hex chars] — verified offline.
        let expected = SHA256.hash(data: Data("/tmp/test".utf8))
            .compactMap { String(format: "%02x", $0) }.joined().prefix(16).description
        let store = Store(projectPath: "/tmp/test")
        #expect(store.projectHash == expected)
    }

    @Test func storePathContainsHash() {
        let store = Store(projectPath: "/any/path")
        #expect(store.storePath.hasSuffix("/\(store.projectHash).enc"))
    }
}

@Suite("Store.readSecrets / writeSecrets")
struct StoreRoundTripTests {
    private func makeKey() -> Data { Data(repeating: 0x42, count: 32) }

    private func makeTempStore() -> (Store, URL) {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let storeDir = base.appendingPathComponent("store")
        return (Store(projectPath: base.path, storeDir: storeDir.path), base)
    }

    @Test func roundTripEmptySecrets() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        try store.ensureStoreDirectory()
        try store.writeSecrets([:], key: key)
        let result = try store.readSecrets(key: key)
        #expect(result.isEmpty)
    }

    @Test func roundTripSingleSecret() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        try store.ensureStoreDirectory()
        try store.writeSecrets(["API_KEY": "abc123"], key: key)
        let result = try store.readSecrets(key: key)
        #expect(result["API_KEY"] == "abc123")
    }

    @Test func roundTripMultipleSecrets() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        let secrets = ["A": "1", "B": "hello world", "C": "it's a value"]
        try store.ensureStoreDirectory()
        try store.writeSecrets(secrets, key: key)
        let result = try store.readSecrets(key: key)
        #expect(result == secrets)
    }

    @Test func roundTripValueWithSpecialChars() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        let value = "line1\nline2\ttab$DOLLAR"
        try store.ensureStoreDirectory()
        try store.writeSecrets(["K": value], key: key)
        let result = try store.readSecrets(key: key)
        #expect(result["K"] == value)
    }

    @Test func readMissingFileReturnsEmpty() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        let result = try store.readSecrets(key: key)
        #expect(result.isEmpty)
    }

    @Test func writeOverwritesPreviousSecrets() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        try store.ensureStoreDirectory()
        try store.writeSecrets(["OLD": "value"], key: key)
        try store.writeSecrets(["NEW": "replaced"], key: key)
        let result = try store.readSecrets(key: key)
        #expect(result["OLD"] == nil)
        #expect(result["NEW"] == "replaced")
    }

    @Test func wrongKeyFailsToDecrypt() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let writeKey = Data(repeating: 0xAA, count: 32)
        let wrongKey = Data(repeating: 0xBB, count: 32)
        try store.ensureStoreDirectory()
        try store.writeSecrets(["X": "y"], key: writeKey)
        #expect(throws: (any Error).self) {
            try store.readSecrets(key: wrongKey)
        }
    }

    @Test func corruptedFileFailsToDecrypt() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        try store.ensureStoreDirectory()
        try store.writeSecrets(["K": "v"], key: key)
        try Data(repeating: 0xFF, count: 64).write(to: URL(fileURLWithPath: store.storePath))
        #expect(throws: (any Error).self) {
            try store.readSecrets(key: key)
        }
    }

    @Test func emptyFileFailsToDecrypt() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        try store.ensureStoreDirectory()
        try Data().write(to: URL(fileURLWithPath: store.storePath))
        #expect(throws: (any Error).self) {
            try store.readSecrets(key: key)
        }
    }

    @Test func roundTripUnicodeValue() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        let value = "日本語🔑émojis: ☕️🎉"
        try store.ensureStoreDirectory()
        try store.writeSecrets(["UNICODE": value], key: key)
        let result = try store.readSecrets(key: key)
        #expect(result["UNICODE"] == value)
    }

    @Test func roundTripManySecrets() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        var secrets: [String: String] = [:]
        for i in 0..<50 {
            secrets["KEY_\(i)"] = "value_\(i)"
        }
        try store.ensureStoreDirectory()
        try store.writeSecrets(secrets, key: key)
        let result = try store.readSecrets(key: key)
        #expect(result == secrets)
    }

    @Test func ensureStoreDirectoryCreatesNestedPath() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let storeDir = (store.storePath as NSString).deletingLastPathComponent
        #expect(!FileManager.default.fileExists(atPath: storeDir))
        try store.ensureStoreDirectory()
        var isDir: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: storeDir, isDirectory: &isDir)
        #expect(exists && isDir.boolValue)
    }
}

@Suite("Store.defaultInit")
struct StoreDefaultInitTests {
    @Test func defaultProjectPathIsCurrentDirectory() {
        let store = Store()
        #expect(store.projectPath == FileManager.default.currentDirectoryPath)
    }

    @Test func defaultStorePathIsInDotBioenv() {
        let store = Store()
        let homeDir = FileManager.default.homeDirectoryForCurrentUser.path
        #expect(store.storePath.hasPrefix("\(homeDir)/.bioenv/"))
    }

    @Test func defaultStorePathEndsWithEncExtension() {
        let store = Store()
        #expect(store.storePath.hasSuffix(".enc"))
    }

    @Test func customStoreDir() {
        let store = Store(projectPath: "/tmp/p", storeDir: "/tmp/mystore")
        #expect(store.storePath.hasPrefix("/tmp/mystore/"))
        #expect(store.storePath.hasSuffix(".enc"))
    }

    @Test func projectPathIsStoredVerbatim() {
        let path = "/Users/testuser/myproject"
        let store = Store(projectPath: path)
        #expect(store.projectPath == path)
    }
}
