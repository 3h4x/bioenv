import Foundation
import Darwin

public enum ExecError: Error, CustomStringConvertible {
    case invalidUsage
    case noCommand
    case invalidEnvironmentEntry(key: String)
    case waitFailed(Int32)
    case childExecutionFailed(command: String, errno: Int32)

    public var description: String {
        switch self {
        case .invalidUsage:
            return "Usage: bioenv exec -- COMMAND [ARGS...]"
        case .noCommand:
            return "Usage: bioenv exec -- COMMAND [ARGS...]"
        case .invalidEnvironmentEntry(let key):
            return "Cannot exec with value for '\(key)' because it contains a NUL byte."
        case .waitFailed(let errno):
            return "Failed to wait for child process: \(String(cString: strerror(errno)))"
        case .childExecutionFailed(let command, let errno):
            return "Failed to execute '\(command)': \(String(cString: strerror(errno)))"
        }
    }
}

public enum Exec {
    public static func command(from args: [String]) throws -> [String] {
        guard args.first == "--" else {
            throw ExecError.invalidUsage
        }

        let command = Array(args.dropFirst())
        guard !command.isEmpty else {
            throw ExecError.noCommand
        }

        return command
    }

    public static func run(command: [String], environment: [String: String]) throws -> Int32 {
        guard !command.isEmpty else {
            throw ExecError.noCommand
        }

        var pid = pid_t()
        let spawnStatus = try withCommandPointers(command) { argv in
            try withEnvironmentPointers(overrides: environment) { envp in
                posix_spawnp(&pid, argv[0], nil, nil, argv, envp)
            }
        }

        guard spawnStatus == 0 else {
            throw ExecError.childExecutionFailed(command: command[0], errno: spawnStatus)
        }

        let status = try waitForChildProcess(pid: pid)

        if exited(status) {
            return exitStatus(status)
        }

        if signaled(status) {
            return 128 + termSignal(status)
        }

        return 1
    }

    internal static func waitForChildProcess(
        pid: pid_t,
        waiter: (pid_t, UnsafeMutablePointer<Int32>, Int32) -> pid_t = waitpid
    ) throws -> Int32 {
        var status: Int32 = 0
        while true {
            if waiter(pid, &status, 0) != -1 {
                return status
            }

            if errno != EINTR {
                throw ExecError.waitFailed(errno)
            }
        }
    }

    internal static func withEnvironmentPointers<R>(
        baseEnvironment: [String: String] = ProcessInfo.processInfo.environment,
        overrides: [String: String],
        onEntryRelease: ((UnsafeMutablePointer<CChar>, Int) -> Void)? = nil,
        _ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) throws -> R
    ) throws -> R {
        let entries = try mergedEnvironmentEntries(
            baseEnvironment: baseEnvironment,
            overrides: overrides
        )
        return try withCStringArray(
            entries: entries.map { .environment(key: $0.key, value: $0.value) },
            onEntryRelease: onEntryRelease,
            body
        )
    }

    private static func mergedEnvironmentEntries(
        baseEnvironment: [String: String],
        overrides: [String: String]
    ) throws -> [(key: String, value: String)] {
        var merged = baseEnvironment
        for (key, value) in overrides {
            guard !key.contains("\0"), !value.contains("\0") else {
                throw ExecError.invalidEnvironmentEntry(key: key)
            }
            merged[key] = value
        }
        return merged.keys.sorted().map { (key: $0, value: merged[$0] ?? "") }
    }

    private static func withCommandPointers<R>(
        _ strings: [String],
        _ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) throws -> R
    ) throws -> R {
        try withCStringArray(entries: strings.map { .string($0) }, body)
    }

    private static func withCStringArray<R>(
        entries: [CStringArrayEntry],
        onEntryRelease: ((UnsafeMutablePointer<CChar>, Int) -> Void)? = nil,
        _ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) throws -> R
    ) throws -> R {
        let buffers = entries.map(Self.allocateCString)
        var pointers: [UnsafeMutablePointer<CChar>?] = buffers.map(\.pointer)
        pointers.append(nil)
        defer {
            for buffer in buffers {
                scrub(pointer: buffer.pointer, length: buffer.length)
                onEntryRelease?(buffer.pointer, buffer.length)
                buffer.pointer.deallocate()
            }
        }

        return try pointers.withUnsafeMutableBufferPointer { buffer in
            try body(buffer.baseAddress!)
        }
    }

    private static func allocateCString(for entry: CStringArrayEntry) -> CStringBuffer {
        switch entry {
        case .string(let string):
            return allocateCString(length: string.utf8.count) { pointer in
                _ = copyUTF8Bytes(from: string, to: pointer, startingAt: 0)
            }
        case .environment(let key, let value):
            let length = key.utf8.count + 1 + value.utf8.count
            return allocateCString(length: length) { pointer in
                var index = copyUTF8Bytes(from: key, to: pointer, startingAt: 0)
                pointer[index] = CChar(bitPattern: UInt8(ascii: "="))
                index += 1
                _ = copyUTF8Bytes(from: value, to: pointer, startingAt: index)
            }
        }
    }

    private static func allocateCString(
        length: Int,
        writeBytes: (UnsafeMutablePointer<CChar>) -> Void
    ) -> CStringBuffer {
        let pointer = UnsafeMutablePointer<CChar>.allocate(capacity: length + 1)
        writeBytes(pointer)
        pointer[length] = 0
        return CStringBuffer(pointer: pointer, length: length)
    }

    private static func copyUTF8Bytes(
        from string: String,
        to pointer: UnsafeMutablePointer<CChar>,
        startingAt startIndex: Int
    ) -> Int {
        var index = startIndex
        for byte in string.utf8 {
            pointer[index] = CChar(bitPattern: byte)
            index += 1
        }
        return index
    }

    private static func scrub(pointer: UnsafeMutablePointer<CChar>, length: Int) {
        guard length > 0 else { return }
        for index in 0..<length {
            pointer[index] = 0
        }
    }

    private static func exited(_ status: Int32) -> Bool {
        (status & 0x7f) == 0
    }

    private static func exitStatus(_ status: Int32) -> Int32 {
        (status >> 8) & 0xff
    }

    private static func signaled(_ status: Int32) -> Bool {
        let signal = status & 0x7f
        return signal != 0 && signal != 0x7f
    }

    private static func termSignal(_ status: Int32) -> Int32 {
        status & 0x7f
    }
}

private struct CStringBuffer {
    let pointer: UnsafeMutablePointer<CChar>
    let length: Int
}

private enum CStringArrayEntry {
    case string(String)
    case environment(key: String, value: String)
}
