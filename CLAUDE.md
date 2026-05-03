# bioenv

Biometric-protected environment variables using macOS Touch ID + Keychain.

## Architecture

- **Language**: Swift 6.x
- **Platform**: macOS only (Touch ID / Secure Enclave)
- **No external dependencies** - uses manual argument parsing, no ArgumentParser

## How It Works

- Each project gets an AES-256-GCM encryption key stored in macOS Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`)
- Touch ID authentication via `LAContext.evaluatePolicy` before any secret access
- Secrets stored in encrypted JSON files at `~/.bioenv/<project-hash>.enc`
- Project identity = SHA-256 of absolute directory path (first 16 hex chars)
- Single Touch ID prompt decrypts all secrets for a project

## Build & Install

```bash
make install   # build release, sign, copy to ~/bin
make setup     # activate .githooks/pre-push (run once after cloning)
```

Or manually:
```bash
swift build -c release
codesign -s - -f .build/release/bioenv
cp .build/release/bioenv ~/bin/
```

## File Structure

```
Sources/bioenv/
  main.swift         # CLI entry, argument parsing, command dispatch (no business logic)
Sources/bioenvLib/
  Keychain.swift     # Keychain CRUD + Touch ID auth via LAContext (Security + LocalAuthentication frameworks)
  Crypto.swift       # AES-256-GCM encrypt/decrypt (CryptoKit)
  Store.swift        # Encrypted JSON file operations, .env parsing, shell escaping
  Config.swift       # Configuration management (~/.bioenv/config.json)
  Version.swift      # appVersion constant ("dev" locally, injected by CI at release time)
Tests/bioenvTests/
  KeychainTests.swift
  CryptoTests.swift
  StoreTests.swift
  ConfigTests.swift
```

## Commands

```
bioenv init              # Create encryption key in Keychain for current directory (no Touch ID)
bioenv set KEY VALUE     # Add/update a secret (Touch ID)
bioenv get KEY           # Get single secret (Touch ID)
bioenv load              # Print export statements for all secrets (Touch ID)
bioenv import FILE       # Bulk import from .env file (Touch ID)
bioenv list              # List key names (Touch ID)
bioenv remove KEY        # Remove a secret (Touch ID)
bioenv status            # Show status for current directory
bioenv destroy           # Delete Keychain key and encrypted store (irreversible)
bioenv config            # Show current configuration
bioenv config sync on|off  # Enable/disable iCloud Keychain sync (default: off, requires Apple Developer cert)
bioenv version             # Show installed version
```

## direnv Integration

`.envrc`:
```bash
eval "$(bioenv load)"
```

## Design Spec

Full design: `docs/superpowers/specs/2026-03-26-bioenv-design.md`

## Coding Conventions

1. Swift 6.x strict concurrency is in effect — all new code must compile without concurrency warnings.
2. Public API lives in `Sources/bioenvLib/`; the `Sources/bioenv/main.swift` executable is thin dispatch only — no business logic there.
3. Declare `public` access on types/functions in `bioenvLib` that tests need; keep implementation details `internal` (default).
4. Errors go to `fputs("Error: ...\n", stderr)`; success output and data go to `print()` / stdout. Never mix them.
5. Use `throws` for all fallible operations; let `main.swift` catch and `exit(1)`.
6. Argument parsing uses manual `CommandLine.arguments` — do not add `ArgumentParser` or any external dependency.
7. Zero sensitive plaintext in memory beyond its point of use: always `defer { data.resetBytes(in: 0..<data.count) }` after decrypting secrets.
8. Use `.write(to:options:.atomic)` for all `.enc` file writes to avoid partial writes.
9. Name library files after their primary type or concern in UpperCamelCase (`Store.swift`, `Keychain.swift`, etc.); keep the executable entrypoint at `Sources/bioenv/main.swift`.
10. Keep imports minimal and explicit to the frameworks a file actually uses; do not add umbrella layers or helper dependencies to hide `Foundation`, `CryptoKit`, `Security`, or `LocalAuthentication`.
11. Keep command names, usage text, and user-facing behavior synchronized across `Sources/bioenv/main.swift`, `README.md`, and the Commands section here whenever the CLI changes.

## Testing

1. Run tests with `swift test`.
2. Tests live in `Tests/bioenvTests/`; use the Swift Testing framework (`@Suite`, `@Test`, `#expect`).
3. Test `bioenvLib` only — `main.swift` dispatch is not unit-tested.
4. Do not mock Keychain or Touch ID; skip integration paths that require hardware. Mark them clearly if added.
5. Use `FileManager.default.temporaryDirectory` + `UUID()` for temp files; always clean up with `defer { try? FileManager.default.removeItem(at: ...) }`.
6. Run `swift test` before every commit.
7. New public functions in `Store`, `Crypto`, or `Keychain` require corresponding tests.
8. Name test files by the production area they cover (`StoreTests.swift`, `CryptoTests.swift`, etc.) and group related assertions with `@Suite` blocks around one behavior or API surface.
9. Prefer regression tests for parsing, quoting, crypto, and error-reporting edge cases when fixing bugs; these have been the highest-churn areas in recent commits.

## Architecture

1. All crypto operations go through `Crypto.swift` (CryptoKit AES-256-GCM only).
2. All Keychain access goes through `Keychain.swift` (Security + LocalAuthentication frameworks).
3. All encrypted-file I/O goes through `Store.swift`.
4. Config (`~/.bioenv/config.json`) is managed exclusively by `Config.swift`.
5. Never call `SecItem*` or `LAContext` directly from outside `Keychain.swift`.
6. Project identity is always the SHA-256 of the absolute directory path, first 16 hex chars. Do not change this scheme — it would break existing stores.
7. Environment-variable validation and shell escaping rules are centralized in `Store.swift`; do not duplicate export formatting or `.env` parsing logic in `main.swift` or tests.

## Dependency & Supply-Chain Security

1. This project intentionally has **zero external Swift Package dependencies**. Keep it that way.
2. Only Apple system frameworks are permitted: `Security`, `LocalAuthentication`, `CryptoKit`, `Foundation`.
3. If a new Swift package dependency is ever required, get explicit user approval, justify it in the commit message, and pin to a specific version tag in `Package.swift`.
4. Because there is no lockfile in this repo, treat any manifest change as supply-chain sensitive: do not add packages, build plugins, or generator tooling without explicit approval and a follow-up audit plan.

## Scope & Safety Rules

1. Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`, `breaking:` prefixes.
2. Never bypass the pre-push hook (`--no-verify`). It runs `swift build` to catch compilation errors before they hit CI.
3. `Version.swift` (`appVersion`) is auto-overwritten by CI during release. Do not edit it manually or commit a non-`"dev"` value.
4. Release is triggered automatically on every push to `main` — ensure `swift test` and `swift build` pass before pushing.
5. The `destroy` command is irreversible (deletes Keychain key + encrypted store). Always describe the consequence and require explicit user confirmation before suggesting or running it.
6. Never commit `.env` files, `.env.local`, or any file containing real secrets.
7. Do not let documentation drift after CLI changes: if you add, remove, or rename a command or flag, update `README.md` and `CLAUDE.md` in the same change.
