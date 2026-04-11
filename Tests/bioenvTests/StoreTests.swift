import Foundation
import Testing
import bioenvLib

@Suite("Store.shellEscape")
struct ShellEscapeTests {
    let store = Store(projectPath: "/tmp/test")

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
}
