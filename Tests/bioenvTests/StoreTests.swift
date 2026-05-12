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

    @Test func nonAsciiWithControlChar() {
        // Non-ASCII printable chars (é, emoji) in a value that also has a control char
        // must pass through verbatim in the $'...' output; they are not hex-escaped.
        #expect(store.shellEscape("café\n") == "$'café\\n'")
        #expect(store.shellEscape("🔑\n") == "$'🔑\\n'")
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

    @Test func accentedLatinIsSingleQuoted() {
        // Non-ASCII letters (é, ñ, etc.) must not bypass quoting via the fast path.
        // Swift's isLetter is Unicode-aware, so without the isASCII guard these
        // would slip through unquoted while emoji (symbols) would not — inconsistent.
        #expect(store.shellEscape("café") == "'café'")
        #expect(store.shellEscape("naïve") == "'naïve'")
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

    // MARK: - Common real-world patterns

    @Test func equalsSignIsSingleQuoted() {
        #expect(store.shellEscape("=") == "'='")
        #expect(store.shellEscape("a=b") == "'a=b'")
    }

    @Test func plusSignIsSingleQuoted() {
        #expect(store.shellEscape("a+b") == "'a+b'")
    }

    @Test func percentSignIsSingleQuoted() {
        #expect(store.shellEscape("100%") == "'100%'")
    }

    @Test func globCharsAreSingleQuoted() {
        #expect(store.shellEscape("*.log") == "'*.log'")
        #expect(store.shellEscape("file?.txt") == "'file?.txt'")
    }

    @Test func tildeIsSingleQuoted() {
        // ~ triggers tilde expansion in shells; must be quoted.
        #expect(store.shellEscape("~/path") == "'~/path'")
    }

    @Test func backtickIsSingleQuoted() {
        // Backtick is safe inside single quotes but must still be quoted (not unquoted).
        #expect(store.shellEscape("a`b") == "'a`b'")
    }

    @Test func semicolonIsSingleQuoted() {
        #expect(store.shellEscape("a;b") == "'a;b'")
    }

    @Test func singleQuoteAloneEscapes() {
        // Single quote → '' "'" '' (empty + double-quoted ' + empty) = '
        #expect(store.shellEscape("'") == "''\"'\"''")
    }

    @Test func standardBase64IsSingleQuoted() {
        // Standard base64 uses +, /, = which are not in the safe set.
        #expect(store.shellEscape("abc+def/ghi==") == "'abc+def/ghi=='")
    }

    @Test func base64urlJwtIsUnquoted() {
        // JWT uses base64url (-, _ instead of +, /) separated by dots — all safe.
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        #expect(store.shellEscape(jwt) == jwt)
    }

    @Test func databaseURLIsSingleQuoted() {
        // @ and ? are not safe; whole URL must be single-quoted.
        let url = "postgres://user@host:5432/db?sslmode=require"
        #expect(store.shellEscape(url) == "'\(url)'")
    }

    @Test func braceExpansionCharsSingleQuoted() {
        #expect(store.shellEscape("${FOO}") == "'${FOO}'")
    }

    @Test func andSignIsSingleQuoted() {
        #expect(store.shellEscape("foo&bar") == "'foo&bar'")
    }

    // MARK: - Whitespace-only values

    @Test func singleSpaceIsSingleQuoted() {
        #expect(store.shellEscape(" ") == "' '")
    }

    @Test func multipleSpacesIsSingleQuoted() {
        #expect(store.shellEscape("   ") == "'   '")
    }

    @Test func tabOnlyUsesAnsiC() {
        // Tab is 0x09 — a control char — so the $'...' path fires.
        #expect(store.shellEscape("\t") == "$'\\t'")
    }

    @Test func mixedSpacesAndTabUsesAnsiC() {
        #expect(store.shellEscape(" \t ") == "$' \\t '")
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

    @Test func repeatedCallsProduceConsistentResults() {
        // Static CharacterSets must give identical answers across many invocations.
        for _ in 0..<500 {
            #expect(Store.isValidEnvVarName("VALID_KEY"))
            #expect(!Store.isValidEnvVarName("1INVALID"))
            #expect(!Store.isValidEnvVarName("café"))
        }
    }
}

@Suite("Store.init")
struct StoreInitTests {
    @Test func relativeProjectPathIsNormalizedToAbsolutePath() {
        let currentDirectory = FileManager.default.currentDirectoryPath
        let store = Store(projectPath: ".")

        #expect(store.projectPath == currentDirectory)
    }

    @Test func equivalentRelativeAndAbsoluteProjectPathsProduceSameProjectHash() {
        let currentDirectory = FileManager.default.currentDirectoryPath
        let absoluteStore = Store(projectPath: currentDirectory, storeDir: "/tmp/bioenv-store-tests")
        let relativeStore = Store(projectPath: "./.", storeDir: "/tmp/bioenv-store-tests")

        #expect(relativeStore.projectPath == currentDirectory)
        #expect(relativeStore.projectHash == absoluteStore.projectHash)
        #expect(relativeStore.storePath == absoluteStore.storePath)
    }

    @Test func parentDirectorySegmentsAreCollapsedBeforeHashing() {
        let currentDirectory = FileManager.default.currentDirectoryPath
        let pathWithParentSegments = ((currentDirectory as NSString).appendingPathComponent("..") as NSString)
            .appendingPathComponent((currentDirectory as NSString).lastPathComponent)

        let canonicalStore = Store(projectPath: currentDirectory)
        let nonCanonicalStore = Store(projectPath: pathWithParentSegments)

        #expect(nonCanonicalStore.projectPath == currentDirectory)
        #expect(nonCanonicalStore.projectHash == canonicalStore.projectHash)
    }

    @Test func tildeInProjectPathIsExpandedToHomeDirectory() {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser.path
        let store = Store(projectPath: "~/myproject")
        #expect(store.projectPath == "\(homeDir)/myproject")
        #expect(!store.projectPath.hasPrefix("~"))
    }

    @Test func tildePathAndExpandedPathProduceSameProjectHash() {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser.path
        let tildeStore = Store(projectPath: "~/myproject", storeDir: "/tmp/bioenv-tilde-tests")
        let expandedStore = Store(projectPath: "\(homeDir)/myproject", storeDir: "/tmp/bioenv-tilde-tests")
        #expect(tildeStore.projectHash == expandedStore.projectHash)
        #expect(tildeStore.storePath == expandedStore.storePath)
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

    private func parseCapturingWarnings(_ content: String) throws -> ([String: String], String) {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString + ".env")
        defer { try? FileManager.default.removeItem(at: url) }
        try content.write(to: url, atomically: true, encoding: .utf8)

        var warnings = ""
        let result = try Store.parseEnvFile(url.path) { warning in
            warnings += warning
        }
        return (result, warnings)
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

    @Test func singleQuotedValueWithInlineCommentStripsComment() throws {
        let result = try parse("KEY='hello world' # comment\n")
        #expect(result["KEY"] == "hello world")
    }

    @Test func doubleQuotedValueWithInlineCommentStripsComment() throws {
        let result = try parse("KEY=\"hello world\" # comment\n")
        #expect(result["KEY"] == "hello world")
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

    @Test func invalidKeyWarningEmitted() throws {
        let (result, standardError) = try parseCapturingWarnings("1INVALID=value\nVALID=ok\n")
        let expectedWarning = "warning: skipping invalid key '1INVALID' (must match [A-Za-z_][A-Za-z0-9_]*)\n"
        #expect(result["1INVALID"] == nil)
        #expect(result["VALID"] == "ok")
        #expect(standardError.contains(expectedWarning))
        #expect(standardError.components(separatedBy: expectedWarning).count == 2)
    }

    @Test func keyWithDashSkipped() throws {
        let result = try parse("HAS-DASH=value\nFOO=bar\n")
        #expect(result["HAS-DASH"] == nil)
        #expect(result["FOO"] == "bar")
    }

    @Test func invalidQuotedMultilineKeyEmitsSingleWarning() throws {
        let (result, standardError) = try parseCapturingWarnings("HAS-DASH='line1\nINNER=shadow\nline3'\nVALID=ok\n")
        let expectedWarning = "warning: skipping invalid key 'HAS-DASH' (must match [A-Za-z_][A-Za-z0-9_]*)\n"
        #expect(result["HAS-DASH"] == nil)
        #expect(result["INNER"] == nil)
        #expect(result["VALID"] == "ok")
        #expect(standardError.contains(expectedWarning))
        #expect(standardError.components(separatedBy: expectedWarning).count == 2)
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

    @Test func mismatchedQuotesThrowParseError() {
        #expect(throws: EnvFileParseError.self) {
            try parse("KEY='mismatch\"\n")
        }
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

    @Test func unicodeKeyWarningEmitted() throws {
        let (result, standardError) = try parseCapturingWarnings("café=value\nVALID=ok\n")
        let expectedWarning = "warning: skipping invalid key 'café' (must match [A-Za-z_][A-Za-z0-9_]*)\n"
        #expect(result["café"] == nil)
        #expect(result["VALID"] == "ok")
        #expect(standardError.contains(expectedWarning))
        #expect(standardError.components(separatedBy: expectedWarning).count == 2)
    }

    @Test func invalidKeyWithMalformedQuotedValueDoesNotBlockFollowingValidKey() throws {
        let result = try parse("HAS-DASH='mismatch\"\nVALID=ok\n")
        #expect(result["HAS-DASH"] == nil)
        #expect(result["VALID"] == "ok")
    }

    @Test func invalidKeyWithQuotedMultilineValueSkipsWholeRecord() throws {
        let result = try parse("HAS-DASH='line1\nline2'\nVALID=ok\n")
        #expect(result["HAS-DASH"] == nil)
        #expect(result["VALID"] == "ok")
    }

    @Test func invalidKeyWithQuotedMultilineValueDoesNotImportInnerAssignments() throws {
        let result = try parse("HAS-DASH='line1\nINNER=shadow\nline3'\nVALID=ok\n")
        #expect(result["HAS-DASH"] == nil)
        #expect(result["INNER"] == nil)
        #expect(result["VALID"] == "ok")
    }

    @Test func invalidKeyWithQuotedMultilineValueContainingOtherQuoteSkipsWholeRecord() throws {
        let result = try parse("HAS-DASH='line1 \" note\nINNER=shadow\nline3'\nVALID=ok\n")
        #expect(result["HAS-DASH"] == nil)
        #expect(result["INNER"] == nil)
        #expect(result["VALID"] == "ok")
    }

    @Test func invalidKeyWithDoubleQuotedInnerLineEndingInQuoteDoesNotImportInnerAssignments() throws {
        let result = try parse("HAS-DASH=\"line1\nsay \"hi\"\nINNER=shadow\nline3\"\nVALID=ok\n")
        #expect(result["HAS-DASH"] == nil)
        #expect(result["INNER"] == nil)
        #expect(result["VALID"] == "ok")
    }

    @Test func invalidKeyWithSingleQuotedInnerLineEndingInQuoteDoesNotImportInnerAssignments() throws {
        let result = try parse("HAS-DASH='line1\nsay 'hi'\nINNER=shadow\nline3'\nVALID=ok\n")
        #expect(result["HAS-DASH"] == nil)
        #expect(result["INNER"] == nil)
        #expect(result["VALID"] == "ok")
    }

    @Test func invalidKeyWithUnterminatedQuotedMultilineValueDoesNotImportInnerAssignments() throws {
        let result = try parse("HAS-DASH='line1\nINNER=shadow\nVALID=ok\n")
        #expect(result["HAS-DASH"] == nil)
        #expect(result["INNER"] == nil)
        #expect(result["VALID"] == nil)
    }

    @Test func invalidKeyWithSingleQuotedBackslashBeforeClosingQuotePreservesFollowingKeys() throws {
        let result = try parse("HAS-DASH='line1\nabc\\'\nVALID=ok\nNEXT=yo\n")
        #expect(result["HAS-DASH"] == nil)
        #expect(result["VALID"] == "ok")
        #expect(result["NEXT"] == "yo")
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

    // MARK: - Edge cases

    @Test func fileWithoutTrailingNewline() throws {
        // Files missing the final newline must still parse the last line.
        let result = try parse("KEY=value")
        #expect(result["KEY"] == "value")
    }

    @Test func tabBeforeInlineCommentStripped() throws {
        // \t counts as whitespace in the \s+# regex, so tab-separated comments strip.
        let result = try parse("KEY=value\t# comment\n")
        #expect(result["KEY"] == "value")
    }

    @Test func valueIsEqualsSign() throws {
        // First '=' splits key/value; subsequent '=' chars belong to the value.
        let result = try parse("KEY==\n")
        #expect(result["KEY"] == "=")
    }

    @Test func whitespaceOnlyLineSkipped() throws {
        let result = try parse("   \n")
        #expect(result.isEmpty)
    }

    // MARK: - BOM handling

    @Test func utf8BomIsStripped() throws {
        // Windows editors prepend a UTF-8 BOM (\u{FEFF}); it must not corrupt the first key.
        let result = try parse("\u{FEFF}KEY=value\n")
        #expect(result["KEY"] == "value")
    }

    @Test func utf8BomOnlyFileIsEmpty() throws {
        // A file containing only a BOM (no keys) should parse to empty.
        let result = try parse("\u{FEFF}")
        #expect(result.isEmpty)
    }

    @Test func utf8BomWithMultipleKeys() throws {
        // BOM must be stripped cleanly so all keys including the first parse correctly.
        let result = try parse("\u{FEFF}A=1\nB=2\n")
        #expect(result["A"] == "1")
        #expect(result["B"] == "2")
    }

    @Test func valueMissingNoNewlineAndMultipleKeys() throws {
        // Last line has no newline; ensure all keys are parsed.
        let result = try parse("A=1\nB=2")
        #expect(result["A"] == "1")
        #expect(result["B"] == "2")
    }

    // MARK: - Unicode values

    @Test func unicodeValuePassesThrough() throws {
        // Non-ASCII characters in values must be stored verbatim.
        let result = try parse("KEY=héllo\n")
        #expect(result["KEY"] == "héllo")
    }

    @Test func emojiValuePassesThrough() throws {
        let result = try parse("KEY=🔑secret\n")
        #expect(result["KEY"] == "🔑secret")
    }

    @Test func cjkValuePassesThrough() throws {
        let result = try parse("KEY=日本語\n")
        #expect(result["KEY"] == "日本語")
    }

    @Test func quotedUnicodeValuePassesThrough() throws {
        let result = try parse("KEY=\"café au lait\"\n")
        #expect(result["KEY"] == "café au lait")
    }

    @Test func physicalMultilineDoubleQuotedValuePreservesNewlines() throws {
        let result = try parse("KEY=\"line1\nline2\"\n")
        #expect(result["KEY"] == "line1\nline2")
    }

    @Test func physicalMultilineSingleQuotedValuePreservesIndentedLines() throws {
        let result = try parse("KEY='line1\n  line2'\n")
        #expect(result["KEY"] == "line1\n  line2")
    }

    @Test func physicalMultilineDoubleQuotedValueAllowsClosingLineComment() throws {
        let result = try parse("KEY=\"line1\nline2\" # comment\n")
        #expect(result["KEY"] == "line1\nline2")
    }

    @Test func physicalMultilineDoubleQuotedValuePreservesEscapedQuotes() throws {
        let result = try parse("KEY=\"line1\nsay \\\"hi\\\"\nline3\"\n")
        #expect(result["KEY"] == "line1\nsay \\\"hi\\\"\nline3")
    }

    @Test func physicalMultilineDoubleQuotedValueWithInnerLineEndingInQuotePreservesWholeValue() throws {
        let result = try parse("KEY=\"line1\nsay \"hi\"\nline3\"\n")
        #expect(result["KEY"] == "line1\nsay \"hi\"\nline3")
    }

    @Test func physicalMultilineSingleQuotedValueAllowsClosingLineComment() throws {
        let result = try parse("KEY='line1\n  line2' # comment\n")
        #expect(result["KEY"] == "line1\n  line2")
    }

    @Test func physicalMultilineSingleQuotedValueWithInnerLineEndingInQuotePreservesWholeValue() throws {
        let result = try parse("KEY='line1\nsay 'hi'\nline3'\n")
        #expect(result["KEY"] == "line1\nsay 'hi'\nline3")
    }

    @Test func singleQuotedValueEndingInBackslashPreservesBackslash() throws {
        let result = try parse("KEY='abc\\'\n")
        #expect(result["KEY"] == "abc\\")
    }

    @Test func physicalMultilineSingleQuotedValueEndingInBackslashPreservesBackslash() throws {
        let result = try parse("KEY='line1\nabc\\'\n")
        #expect(result["KEY"] == "line1\nabc\\")
    }

    // MARK: - Quotes inside matching quotes

    @Test func doubleQuotedValueContainingSingleQuote() throws {
        // Double-quoted string with an embedded single quote must preserve it verbatim.
        let result = try parse("KEY=\"it's a secret\"\n")
        #expect(result["KEY"] == "it's a secret")
    }

    @Test func singleQuotedValueContainingDoubleQuote() throws {
        // Single-quoted string with embedded double quotes must preserve them verbatim.
        let result = try parse("KEY='say \"hi\"'\n")
        #expect(result["KEY"] == "say \"hi\"")
    }

    @Test func singleQuotedValueContainingOnlyDoubleQuote() throws {
        // A double quote char is the entire payload of a single-quoted string.
        let result = try parse("KEY='\"'\n")
        #expect(result["KEY"] == "\"")
    }

    @Test func doubleQuotedValueContainingOnlySingleQuote() throws {
        // A single quote char is the entire payload of a double-quoted string.
        let result = try parse("KEY=\"'\"\n")
        #expect(result["KEY"] == "'")
    }

    @Test func singleCharValueIsSingleQuoteThrows() {
        #expect(throws: EnvFileParseError.self) {
            try parse("KEY='\n")
        }
    }

    @Test func singleCharValueIsDoubleQuoteThrows() {
        #expect(throws: EnvFileParseError.self) {
            try parse("KEY=\"\n")
        }
    }

    @Test func mismatchedQuotesDoubleOpenSingleCloseThrows() {
        #expect(throws: EnvFileParseError.self) {
            try parse("KEY=\"mismatch'\n")
        }
    }

    @Test func unterminatedPhysicalMultilineQuotedValueThrows() {
        #expect(throws: EnvFileParseError.self) {
            try parse("KEY=\"line1\nline2\n")
        }
    }

    // MARK: - Backslash sequences in double-quoted values are NOT interpolated

    @Test func doubleQuotedBackslashNIsLiteral() throws {
        // parseEnvFile does not interpret \n as newline — it stores the literal two chars.
        let result = try parse("KEY=\"line1\\nline2\"\n")
        #expect(result["KEY"] == "line1\\nline2")
    }

    @Test func doubleQuotedBackslashTIsLiteral() throws {
        let result = try parse("KEY=\"col1\\tcol2\"\n")
        #expect(result["KEY"] == "col1\\tcol2")
    }

    @Test func doubleQuotedEscapedQuoteIsLiteral() throws {
        // \" inside double quotes is kept verbatim as the two chars \ and ".
        let result = try parse("KEY=\"say \\\"hi\\\"\"\n")
        #expect(result["KEY"] == "say \\\"hi\\\"")
    }

    @Test func doubleQuotedValueEndingInEscapedQuoteThrows() {
        #expect(throws: EnvFileParseError.self) {
            try parse("KEY=\"abc\\\"\n")
        }
    }

    // MARK: - Trailing whitespace in unquoted values

    @Test func trailingWhitespaceStrippedFromUnquotedValue() throws {
        let result = try parse("KEY=value   \n")
        #expect(result["KEY"] == "value")
    }

    @Test func trailingTabStrippedFromUnquotedValue() throws {
        let result = try parse("KEY=value\t\n")
        #expect(result["KEY"] == "value")
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

    @Test func ensureStoreDirectoryIsIdempotent() throws {
        // Calling ensureStoreDirectory twice must not throw even when the dir exists.
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        try store.ensureStoreDirectory()
        #expect(throws: Never.self) {
            try store.ensureStoreDirectory()
        }
    }

    @Test func writeSecretsWithExistingDirectorySucceeds() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        // Pre-create the directory so writeSecrets encounters an existing dir.
        try store.ensureStoreDirectory()
        try store.writeSecrets(["PRE": "exists"], key: key)
        let result = try store.readSecrets(key: key)
        #expect(result["PRE"] == "exists")
    }

    @Test func writeSecretsCreatesDirectoryIfMissing() throws {
        // writeSecrets calls ensureStoreDirectory() internally — callers need not
        // pre-create the store directory.
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        try store.writeSecrets(["AUTO": "created"], key: key)
        let result = try store.readSecrets(key: key)
        #expect(result["AUTO"] == "created")
    }

    @Test func readSecretsThrowsWhenDecryptedDataIsNotJSON() throws {
        // AES-GCM decrypts successfully but the plaintext is not valid JSON.
        // readSecrets must propagate the JSONDecoder error rather than silently
        // returning empty or crashing.
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        try store.ensureStoreDirectory()
        let notJSON = Data("this is not valid JSON".utf8)
        let ciphertext = try Crypto.encrypt(data: notJSON, key: key)
        try ciphertext.write(to: URL(fileURLWithPath: store.storePath))
        #expect(throws: (any Error).self) {
            try store.readSecrets(key: key)
        }
    }

    @Test func readSecretsThrowsWhenDecryptedDataIsJSONArray() throws {
        // A JSON array decrypts fine but cannot be decoded as [String:String].
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        try store.ensureStoreDirectory()
        let arrayJSON = Data("[\"not\",\"a\",\"dict\"]".utf8)
        let ciphertext = try Crypto.encrypt(data: arrayJSON, key: key)
        try ciphertext.write(to: URL(fileURLWithPath: store.storePath))
        #expect(throws: (any Error).self) {
            try store.readSecrets(key: key)
        }
    }

    @Test func readSecretsRejectsInvalidSecretKeyInDecryptedStore() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        try store.ensureStoreDirectory()
        let invalidSecrets = Data(#"{"BAD-KEY":"value","GOOD_KEY":"ok"}"#.utf8)
        let ciphertext = try Crypto.encrypt(data: invalidSecrets, key: key)
        try ciphertext.write(to: URL(fileURLWithPath: store.storePath))

        do {
            _ = try store.readSecrets(key: key)
            Issue.record("Expected invalid secret key to be rejected")
        } catch let error as StoreError {
            #expect(error == .invalidSecretKey("BAD-KEY"))
        } catch {
            Issue.record("Expected StoreError.invalidSecretKey, got \(error)")
        }
    }

    @Test func writeSecretsRejectsInvalidSecretKey() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()

        do {
            try store.writeSecrets(["BAD-KEY": "value", "GOOD_KEY": "ok"], key: key)
            Issue.record("Expected invalid secret key to be rejected on write")
        } catch let error as StoreError {
            #expect(error == .invalidSecretKey("BAD-KEY"))
        } catch {
            Issue.record("Expected StoreError.invalidSecretKey, got \(error)")
        }
    }

    @Test func writeSecretsPersistsValidSecretKeys() throws {
        let (store, base) = makeTempStore()
        defer { try? FileManager.default.removeItem(at: base) }
        let key = makeKey()
        let secrets = ["GOOD_KEY": "ok", "_ALSO_VALID_2": "value"]

        try store.writeSecrets(secrets, key: key)

        let restored = try store.readSecrets(key: key)
        #expect(restored == secrets)
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

    @Test func absoluteCanonicalPathIsUnchangedAfterNormalization() {
        // An already-absolute, already-canonical path has no `.`, `..`, or `~`
        // segments, so normalizeProjectPath leaves it unchanged.
        let path = "/Users/testuser/myproject"
        let store = Store(projectPath: path)
        #expect(store.projectPath == path)
    }
}
