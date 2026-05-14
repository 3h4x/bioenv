import Foundation
import bioenvLib

func failUsage(_ lines: [String]) -> Never {
    for line in lines {
        fputs(line + "\n", stderr)
    }
    exit(1)
}

func requireExactArgumentCount(_ args: [String], count: Int, usageLines: [String]) {
    guard args.count == count else {
        failUsage(usageLines)
    }
}

func printUsage() {
    let usage = """
    bioenv \(appVersion) - Biometric-protected environment variables

    Usage:
      bioenv init                  Initialize bioenv for current directory
      bioenv set KEY VALUE         Set a secret
      bioenv set KEY               Set a secret from stdin
      bioenv get KEY               Get a secret value
      bioenv load                  Print all secrets as export statements
      bioenv exec -- COMMAND ...   Run a command with project secrets in its environment
      bioenv import FILE           Import secrets from .env file
      bioenv list                  List secret key names
      bioenv remove KEY            Remove a secret
      bioenv status                Show status for current directory
      bioenv destroy               Delete Keychain key and encrypted store
      bioenv config                Show current configuration
      bioenv config sync on|off    Enable/disable iCloud Keychain sync (default: off)
      bioenv version               Show version
      bioenv --version             Show version
      bioenv help                  Show this usage text
      bioenv --help | -h           Show this usage text
    """
    fputs(usage + "\n", stderr)
}

ProcessInfo.processInfo.processName = "bioenv \(appVersion)"
let args = Array(CommandLine.arguments.dropFirst())
let dirPath = FileManager.default.currentDirectoryPath
    .replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "~")

guard let command = args.first else {
    printUsage()
    exit(1)
}

if command == "version" || command == "--version" {
    requireExactArgumentCount(args, count: 1, usageLines: ["Usage: bioenv \(command)"])
    print("bioenv \(appVersion)")
    exit(0)
}

if command == "help" || command == "--help" || command == "-h" {
    requireExactArgumentCount(args, count: 1, usageLines: ["Usage: bioenv help | --help | -h"])
    printUsage()
    exit(0)
}

do {
    let config = BioenvConfig.load()
    let store = Store()

    switch command {
    case "init":
        requireExactArgumentCount(args, count: 1, usageLines: ["Usage: bioenv init"])
        let encKey = try Keychain.getOrCreateKey(projectHash: store.projectHash, syncable: config.sync)
        try store.ensureStoreDirectory()
        if !FileManager.default.fileExists(atPath: store.storePath) {
            try store.writeSecrets([:], key: encKey)
        }
        let envrcPath = "\(store.projectPath)/.envrc"
        if !FileManager.default.fileExists(atPath: envrcPath) {
            try "eval \"$(bioenv load)\"\n".write(toFile: envrcPath, atomically: true, encoding: .utf8)
            print("Created .envrc")
        }
        print("bioenv initialized for \(store.projectPath)")
        print("Store: \(store.storePath)")

    case "set":
        guard args.count >= 2 else {
            fputs("Usage: bioenv set KEY VALUE\n", stderr)
            fputs("       echo VALUE | bioenv set KEY\n", stderr)
            exit(1)
        }
        let key = args[1]
        guard Store.isValidEnvVarName(key) else {
            fputs("Invalid key '\(key)': must match [A-Za-z_][A-Za-z0-9_]*\n", stderr)
            exit(1)
        }
        let value: String
        if args.count >= 3 {
            if args.count > 3 {
                fputs("Too many arguments: VALUE must be a single argument.\n", stderr)
                fputs("Use quotes for values with spaces: bioenv set KEY 'hello world'\n", stderr)
                fputs("Or pipe via stdin:                 echo VALUE | bioenv set KEY\n", stderr)
                exit(1)
            }
            value = args[2]
        } else {
            // Read all stdin so multi-line values (PEM keys, certificates) are
            // stored intact, not silently truncated at the first newline.
            let raw = FileHandle.standardInput.readDataToEndOfFile()
            guard !raw.isEmpty, let stdinString = String(data: raw, encoding: .utf8) else {
                fputs("Usage: bioenv set KEY VALUE\n", stderr)
                exit(1)
            }
            value = Store.stripOneTrailingNewline(stdinString)
        }

        try Keychain.authenticate(reason: "\nbioenv (\(appVersion)) is trying to set var in:\n\(dirPath)\n\nAuthenticate to continue")
        let encKey = try Keychain.getOrCreateKey(projectHash: store.projectHash, syncable: config.sync)
        try store.ensureStoreDirectory()
        var secrets = try store.readSecrets(key: encKey)
        secrets[key] = value
        try store.writeSecrets(secrets, key: encKey)
        print("Set \(key)")

    case "get":
        requireExactArgumentCount(args, count: 2, usageLines: ["Usage: bioenv get KEY"])
        let key = args[1]
        guard Store.isValidEnvVarName(key) else {
            fputs("Invalid key '\(key)': must match [A-Za-z_][A-Za-z0-9_]*\n", stderr)
            exit(1)
        }
        try Keychain.authenticate(reason: "\nbioenv (\(appVersion)) is trying to get var from:\n\(dirPath)\n\nAuthenticate to continue")
        let encKey = try Keychain.getKey(projectHash: store.projectHash)
        let secrets = try store.readSecrets(key: encKey)
        guard let value = secrets[key] else {
            fputs("Key '\(key)' not found\n", stderr)
            exit(1)
        }
        print(value)

    case "load":
        requireExactArgumentCount(args, count: 1, usageLines: ["Usage: bioenv load"])
        try Keychain.authenticate(reason: "\nbioenv (\(appVersion)) is trying to load vars from:\n\(dirPath)\n\nAuthenticate to continue")
        let encKey = try Keychain.getKey(projectHash: store.projectHash)
        let secrets = try store.readSecrets(key: encKey)
        for (key, value) in secrets.sorted(by: { $0.key < $1.key }) {
            print("export \(key)=\(store.shellEscape(value))")
        }

    case "exec":
        let commandToRun = try Exec.command(from: Array(args.dropFirst()))
        try Keychain.authenticate(reason: "\nbioenv (\(appVersion)) is trying to run a command with vars from:\n\(dirPath)\n\nAuthenticate to continue")
        let encKey = try Keychain.getKey(projectHash: store.projectHash)
        var secrets = try store.readSecrets(key: encKey)
        defer { secrets.removeAll(keepingCapacity: false) }
        let exitCode = try Exec.run(command: commandToRun, environment: secrets)
        exit(exitCode)

    case "import":
        requireExactArgumentCount(args, count: 2, usageLines: ["Usage: bioenv import FILE"])
        let file = args[1]
        try Keychain.authenticate(reason: "\nbioenv (\(appVersion)) is trying to import vars into:\n\(dirPath)\n\nAuthenticate to continue")
        let encKey = try Keychain.getOrCreateKey(projectHash: store.projectHash, syncable: config.sync)
        try store.ensureStoreDirectory()
        var secrets = try store.readSecrets(key: encKey)
        let imported = try Store.parseEnvFile(file)
        for (key, value) in imported {
            secrets[key] = value
        }
        try store.writeSecrets(secrets, key: encKey)
        print("Imported \(imported.count) secrets from \(file)")

    case "list":
        requireExactArgumentCount(args, count: 1, usageLines: ["Usage: bioenv list"])
        try Keychain.authenticate(reason: "\nbioenv (\(appVersion)) is trying to list vars in:\n\(dirPath)\n\nAuthenticate to continue")
        let encKey = try Keychain.getKey(projectHash: store.projectHash)
        let secrets = try store.readSecrets(key: encKey)
        for key in secrets.keys.sorted() {
            print(key)
        }

    case "remove":
        requireExactArgumentCount(args, count: 2, usageLines: ["Usage: bioenv remove KEY"])
        let key = args[1]
        guard Store.isValidEnvVarName(key) else {
            fputs("Invalid key '\(key)': must match [A-Za-z_][A-Za-z0-9_]*\n", stderr)
            exit(1)
        }
        try Keychain.authenticate(reason: "\nbioenv (\(appVersion)) is trying to remove var from:\n\(dirPath)\n\nAuthenticate to continue")
        let encKey = try Keychain.getKey(projectHash: store.projectHash)
        var secrets = try store.readSecrets(key: encKey)
        guard secrets.removeValue(forKey: key) != nil else {
            fputs("Key '\(key)' not found\n", stderr)
            exit(1)
        }
        try store.writeSecrets(secrets, key: encKey)
        print("Removed \(key)")

    case "status":
        requireExactArgumentCount(args, count: 1, usageLines: ["Usage: bioenv status"])
        print("Directory: \(store.projectPath)")
        print("Project hash: \(store.projectHash)")
        print("Store: \(store.storePath)")
        let hasStore = FileManager.default.fileExists(atPath: store.storePath)
        print("Initialized: \(hasStore ? "yes" : "no")")
        let keychainService = Keychain.serviceName(for: store.projectHash)
        print("Keychain service: \(keychainService)")
        let hasKey = try Keychain.hasKey(projectHash: store.projectHash)
        print("Keychain key: \(hasKey ? "present" : "missing")")
        let envrcPath = "\(store.projectPath)/.envrc"
        let hasEnvrc = FileManager.default.fileExists(atPath: envrcPath)
        print(".envrc: \(hasEnvrc ? "present" : "missing")")
        if hasStore, hasKey {
            try Keychain.authenticate(reason: "\nbioenv (\(appVersion)) is trying to access secrets in:\n\(dirPath)\n\nAuthenticate to continue")
            let encKey = try Keychain.getKey(projectHash: store.projectHash)
            let secrets = try store.readSecrets(key: encKey)
            print("Secrets: \(secrets.count)")
        }

    case "destroy":
        requireExactArgumentCount(args, count: 1, usageLines: ["Usage: bioenv destroy"])
        print("Directory: \(store.projectPath)")
        print("Keychain service: \(Keychain.serviceName(for: store.projectHash))")
        print("Store: \(store.storePath)")
        fputs("This will delete the Keychain key and encrypted store. Continue? [y/N] ", stderr)
        guard let answer = readLine(), answer.lowercased() == "y" else {
            print("Aborted")
            exit(0)
        }
        try Keychain.deleteKey(projectHash: store.projectHash)
        if FileManager.default.fileExists(atPath: store.storePath) {
            try FileManager.default.removeItem(atPath: store.storePath)
        }
        print("Destroyed bioenv for \(store.projectPath)")

    case "config":
        if args.count < 2 {
            requireExactArgumentCount(args, count: 1, usageLines: ["Usage: bioenv config"])
            print("sync: \(config.sync ? "on" : "off") (iCloud Keychain sync)")
        } else if args[1] == "sync" {
            requireExactArgumentCount(args, count: 3, usageLines: ["Usage: bioenv config sync on|off"])
            var newConfig = config
            switch args[2] {
            case "on", "true", "yes":
                newConfig.sync = true
            case "off", "false", "no":
                newConfig.sync = false
            default:
                fputs("Usage: bioenv config sync on|off\n", stderr)
                exit(1)
            }
            try newConfig.save()
            print("sync: \(newConfig.sync ? "on" : "off")")
            if newConfig.sync != config.sync {
                print("Note: existing projects keep their current sync setting. Re-init to change them.")
            }
        } else {
            fputs("Usage: bioenv config sync on|off\n", stderr)
            exit(1)
        }

    default:
        fputs("Unknown command: \(command)\n", stderr)
        printUsage()
        exit(1)
    }
} catch {
    fputs("Error: \(ErrorFormatting.userMessage(for: error))\n", stderr)
    exit(1)
}
