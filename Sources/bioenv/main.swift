import Foundation

func printUsage() {
    let usage = """
    bioenv - Biometric-protected environment variables

    Usage:
      bioenv init                  Initialize bioenv for current directory
      bioenv set KEY VALUE         Set a secret
      bioenv get KEY               Get a secret value
      bioenv load                  Print all secrets as export statements
      bioenv import FILE           Import secrets from .env file
      bioenv list                  List secret key names
      bioenv remove KEY            Remove a secret
      bioenv status                Show status for current directory
      bioenv destroy               Delete Keychain key and encrypted store
      bioenv config                Show current configuration
      bioenv config sync on|off    Enable/disable iCloud Keychain sync (default: on)
    """
    fputs(usage + "\n", stderr)
}

let args = Array(CommandLine.arguments.dropFirst())

guard let command = args.first else {
    printUsage()
    exit(1)
}

do {
    let config = BioenvConfig.load()
    let store = Store()

    switch command {
    case "init":
        let _ = try Keychain.getOrCreateKey(projectHash: store.projectHash, syncable: config.sync)
        try store.ensureStoreDirectory()
        if !FileManager.default.fileExists(atPath: store.storePath) {
            try store.writeSecrets([:], key: try Keychain.getKey(projectHash: store.projectHash))
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
        let value: String
        if args.count >= 3 {
            value = args[2]
        } else if let stdin = readLine(strippingNewline: true) {
            value = stdin
        } else {
            fputs("Usage: bioenv set KEY VALUE\n", stderr)
            exit(1)
        }

        try Keychain.authenticate(reason: "Access bioenv secrets")
        let encKey = try Keychain.getOrCreateKey(projectHash: store.projectHash, syncable: config.sync)
        try store.ensureStoreDirectory()
        var secrets = try store.readSecrets(key: encKey)
        secrets[key] = value
        try store.writeSecrets(secrets, key: encKey)
        print("Set \(key)")

    case "get":
        guard args.count >= 2 else {
            fputs("Usage: bioenv get KEY\n", stderr)
            exit(1)
        }
        let key = args[1]
        try Keychain.authenticate(reason: "Access bioenv secrets")
        let encKey = try Keychain.getKey(projectHash: store.projectHash)
        let secrets = try store.readSecrets(key: encKey)
        guard let value = secrets[key] else {
            fputs("Key '\(key)' not found\n", stderr)
            exit(1)
        }
        print(value)

    case "load":
        try Keychain.authenticate(reason: "Access bioenv secrets")
        let encKey = try Keychain.getKey(projectHash: store.projectHash)
        let secrets = try store.readSecrets(key: encKey)
        for (key, value) in secrets.sorted(by: { $0.key < $1.key }) {
            print("export \(key)=\(store.shellEscape(value))")
        }

    case "import":
        guard args.count >= 2 else {
            fputs("Usage: bioenv import FILE\n", stderr)
            exit(1)
        }
        let file = args[1]
        try Keychain.authenticate(reason: "Access bioenv secrets")
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
        try Keychain.authenticate(reason: "Access bioenv secrets")
        let encKey = try Keychain.getKey(projectHash: store.projectHash)
        let secrets = try store.readSecrets(key: encKey)
        for key in secrets.keys.sorted() {
            print(key)
        }

    case "remove":
        guard args.count >= 2 else {
            fputs("Usage: bioenv remove KEY\n", stderr)
            exit(1)
        }
        let key = args[1]
        try Keychain.authenticate(reason: "Access bioenv secrets")
        let encKey = try Keychain.getKey(projectHash: store.projectHash)
        var secrets = try store.readSecrets(key: encKey)
        guard secrets.removeValue(forKey: key) != nil else {
            fputs("Key '\(key)' not found\n", stderr)
            exit(1)
        }
        try store.writeSecrets(secrets, key: encKey)
        print("Removed \(key)")

    case "status":
        print("Directory: \(store.projectPath)")
        print("Project hash: \(store.projectHash)")
        print("Store: \(store.storePath)")
        let hasStore = FileManager.default.fileExists(atPath: store.storePath)
        print("Initialized: \(hasStore ? "yes" : "no")")
        let keychainService = "com.bioenv.\(store.projectHash)"
        print("Keychain service: \(keychainService)")
        let hasKey = (try? Keychain.getKey(projectHash: store.projectHash)) != nil
        print("Keychain key: \(hasKey ? "present" : "missing")")
        let envrcPath = "\(store.projectPath)/.envrc"
        let hasEnvrc = FileManager.default.fileExists(atPath: envrcPath)
        print(".envrc: \(hasEnvrc ? "present" : "missing")")
        if hasStore && hasKey {
            try Keychain.authenticate(reason: "Access bioenv secrets")
            let encKey = try Keychain.getKey(projectHash: store.projectHash)
            let secrets = try store.readSecrets(key: encKey)
            print("Secrets: \(secrets.count)")
        }

    case "destroy":
        print("Directory: \(store.projectPath)")
        print("Keychain service: com.bioenv.\(store.projectHash)")
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
            print("sync: \(config.sync ? "on" : "off") (iCloud Keychain sync)")
        } else if args.count >= 3 && args[1] == "sync" {
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
    fputs("Error: \(error)\n", stderr)
    exit(1)
}
