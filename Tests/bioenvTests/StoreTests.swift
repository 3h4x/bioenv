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
