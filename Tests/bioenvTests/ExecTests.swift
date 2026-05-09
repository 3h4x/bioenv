import Foundation
import Darwin
import Testing
@testable import bioenvLib

@Suite("Exec")
struct ExecTests {
    @Test func commandRequiresSeparator() {
        #expect(throws: ExecError.self) {
            _ = try Exec.command(from: ["env"])
        }
    }

    @Test func commandRequiresExecutableAfterSeparator() {
        #expect(throws: ExecError.self) {
            _ = try Exec.command(from: ["--"])
        }
    }

    @Test func commandRejectsNulContainingArgumentBeforeSpawn() {
        do {
            _ = try Exec.command(from: ["--", "/bin/echo", "hello\0world"])
            Issue.record("Expected Exec.command to reject NUL-containing command argument")
        } catch let error as ExecError {
            #expect(
                error.description ==
                "Cannot exec because command argument 2 contains a NUL byte."
            )
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test func injectsSecretsOnlyIntoChildProcess() throws {
        unsetenv("BIOENV_EXEC_TEST_SECRET")

        let command = ["/usr/bin/env"]
        let output = try captureStandardOutput {
            let status = try Exec.run(
                command: command,
                environment: ["BIOENV_EXEC_TEST_SECRET": "child-only"]
            )
            #expect(status == 0)
        }

        #expect(output.contains("BIOENV_EXEC_TEST_SECRET=child-only"))
        #expect(ProcessInfo.processInfo.environment["BIOENV_EXEC_TEST_SECRET"] == nil)
    }

    @Test func childExitStatusIsPropagated() throws {
        let status = try Exec.run(
            command: ["/bin/sh", "-c", "exit 23"],
            environment: [:]
        )

        #expect(status == 23)
    }

    @Test func waitRetriesWhenInterrupted() throws {
        var attempts = 0

        let status = try Exec.waitForChildProcess(pid: 42) { pid, statusPointer, options in
            #expect(pid == 42)
            #expect(options == 0)
            attempts += 1

            if attempts == 1 {
                errno = EINTR
                return -1
            }

            statusPointer.pointee = 23 << 8
            return pid
        }

        #expect(attempts == 2)
        #expect(status == 23 << 8)
    }

    @Test func missingExecutableThrowsReadableError() {
        #expect(throws: ExecError.self) {
            _ = try Exec.run(
                command: ["/definitely/missing/bioenv-exec-test"],
                environment: [:]
            )
        }
    }

    @Test func execRejectsNulContainingSecretBeforeSpawn() {
        do {
            _ = try Exec.run(
                command: ["/usr/bin/env"],
                environment: ["BIOENV_EXEC_TEST_SECRET": "child\0only"]
            )
            Issue.record("Expected Exec.run to reject NUL-containing secret")
        } catch let error as ExecError {
            #expect(
                error.description ==
                "Cannot exec with value for 'BIOENV_EXEC_TEST_SECRET' because it contains a NUL byte."
            )
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test func execRejectsNulContainingExecutableBeforeSpawn() {
        do {
            _ = try Exec.run(
                command: ["/usr/bin\0/env"],
                environment: [:]
            )
            Issue.record("Expected Exec.run to reject NUL-containing executable")
        } catch let error as ExecError {
            #expect(
                error.description ==
                "Cannot exec because command argument 1 contains a NUL byte."
            )
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test func environmentBuffersAreScrubbedAfterSuccessfulUse() throws {
        let expected = Array("BIOENV_EXEC_TEST_SECRET=child-only".utf8)
        var sawScrubbedBuffer = false

        try Exec.withEnvironmentPointers(
            baseEnvironment: [:],
            overrides: ["BIOENV_EXEC_TEST_SECRET": "child-only"],
            onEntryRelease: { pointer, length in
                let bytes = (0..<length).map { UInt8(bitPattern: pointer[$0]) }
                if length == expected.count {
                    sawScrubbedBuffer = true
                    #expect(bytes == Array(repeating: 0, count: expected.count))
                }
            },
            { _ in }
        )

        #expect(sawScrubbedBuffer)
    }

    @Test func environmentEntryContainsSecretBeforeRelease() throws {
        let expected = Array("BIOENV_EXEC_TEST_SECRET=child-only".utf8)
        var sawExpectedEntry = false

        try Exec.withEnvironmentPointers(
            baseEnvironment: ["PATH": "/usr/bin"],
            overrides: ["BIOENV_EXEC_TEST_SECRET": "child-only"],
            { envp in
                var index = 0
                while let entry = envp[index] {
                    if cStringBytes(entry) == expected {
                        sawExpectedEntry = true
                    }
                    index += 1
                }
            }
        )

        #expect(sawExpectedEntry)
    }

    @Test func environmentPointersRejectNulContainingSecretBeforeBodyRuns() {
        var bodyRan = false

        do {
            try Exec.withEnvironmentPointers(
                baseEnvironment: ["PATH": "/usr/bin"],
                overrides: ["BIOENV_EXEC_TEST_SECRET": "child\0only"],
                { _ in
                    bodyRan = true
                }
            )
            Issue.record("Expected withEnvironmentPointers to reject NUL-containing secret")
        } catch let error as ExecError {
            #expect(
                error.description ==
                "Cannot exec with value for 'BIOENV_EXEC_TEST_SECRET' because it contains a NUL byte."
            )
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        #expect(bodyRan == false)
    }

    @Test func environmentBuffersAreScrubbedWhenBodyThrows() {
        enum SampleFailure: Error {
            case boom
        }

        let expected = Array("BIOENV_EXEC_TEST_SECRET=child-only".utf8)
        var sawScrubbedBuffer = false

        #expect(throws: SampleFailure.self) {
            try Exec.withEnvironmentPointers(
                baseEnvironment: [:],
                overrides: ["BIOENV_EXEC_TEST_SECRET": "child-only"],
                onEntryRelease: { pointer, length in
                    let bytes = (0..<length).map { UInt8(bitPattern: pointer[$0]) }
                    if length == expected.count {
                        sawScrubbedBuffer = true
                        #expect(bytes == Array(repeating: 0, count: expected.count))
                    }
                },
                { _ in
                    throw SampleFailure.boom
                }
            )
        }

        #expect(sawScrubbedBuffer)
    }

    private func captureStandardOutput(_ body: () throws -> Void) throws -> String {
        let pipe = Pipe()
        let stdoutFD = dup(STDOUT_FILENO)
        #expect(stdoutFD >= 0)

        defer {
            pipe.fileHandleForReading.closeFile()
        }

        fflush(stdout)
        dup2(pipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)

        try body()

        fflush(stdout)
        dup2(stdoutFD, STDOUT_FILENO)
        close(stdoutFD)
        pipe.fileHandleForWriting.closeFile()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(decoding: data, as: UTF8.self)
    }

    private func cStringBytes(_ pointer: UnsafeMutablePointer<CChar>) -> [UInt8] {
        var bytes: [UInt8] = []
        var index = 0
        while pointer[index] != 0 {
            bytes.append(UInt8(bitPattern: pointer[index]))
            index += 1
        }
        return bytes
    }
}
