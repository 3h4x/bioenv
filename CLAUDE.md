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
make install              # download latest release binary from GitHub, sign, copy to ~/bin
make install-from-source  # build locally, sign, copy to ~/bin
make setup                # activate .githooks/pre-push (run once after cloning)
```

Or manually:
```bash
swift build -c release
codesign -s - -f .build/release/bioenv
rm -f ~/bin/bioenv && cp .build/release/bioenv ~/bin/
```

Always `rm -f` the old binary before copying a new one into `~/bin`. Overwriting it in place keeps the same inode, and macOS caches code-signature state per inode — the next launch is killed with `SIGKILL (Code Signature Invalid)` / `Taskgated Invalid Signature` even though `codesign --verify` passes. Both `make install` targets already do this.

## File Structure

```
Sources/bioenv/
  main.swift         # CLI entry, argument parsing, command dispatch (no business logic)
Sources/bioenvLib/
  Keychain.swift     # Keychain CRUD + Touch ID auth via LAContext (Security + LocalAuthentication frameworks)
  Crypto.swift       # AES-256-GCM encrypt/decrypt (CryptoKit)
  Exec.swift         # Subprocess command parsing, env injection, and secure buffer scrubbing
  Store.swift        # Encrypted JSON file operations, .env parsing, shell escaping
  Config.swift       # Configuration management (~/.bioenv/config.json)
  ErrorFormatting.swift  # User-facing error normalization
  Version.swift      # appVersion constant ("dev" locally, injected by CI at release time)
Tests/bioenvTests/
  KeychainTests.swift
  CryptoTests.swift
  ExecTests.swift
  StoreTests.swift
  ConfigTests.swift
  ErrorFormattingTests.swift
```

## Commands

```
bioenv init              # Create encryption key in Keychain for current directory (no Touch ID)
bioenv set KEY VALUE     # Add/update a secret (Touch ID)
bioenv set KEY           # Add/update a secret — reads VALUE from stdin until EOF, strips one trailing newline (Touch ID)
bioenv get KEY           # Get single secret (Touch ID)
bioenv load              # Print export statements for all secrets (Touch ID)
bioenv exec -- COMMAND [ARGS...]  # Run one command with project secrets in its environment (Touch ID)
bioenv import FILE       # Bulk import from .env file (Touch ID)
bioenv list              # List key names (Touch ID)
bioenv remove KEY        # Remove a secret — aliases: rm, del (Touch ID)
bioenv status            # Show status for current directory
bioenv destroy           # Delete Keychain key and encrypted store (irreversible)
bioenv config            # Show current configuration
bioenv config sync on|off|true|false|yes|no  # Enable/disable iCloud Keychain sync (default: off, requires Apple Developer cert)
bioenv version             # Show installed version
bioenv --version           # Alias for version
bioenv help | --help | -h  # Show usage text
```

## direnv Integration

`.envrc`:
```bash
eval "$(bioenv load)"
```

## Docs Reference

| File | Topic | Load when |
| --- | --- | --- |
| `docs/superpowers/specs/2026-05-08-exec-command-security.md` | Security and lifecycle constraints for `bioenv exec -- COMMAND [ARGS...]`, including NUL-byte rejection, environment injection scope, and buffer zeroing. | Read before changing `Sources/bioenvLib/Exec.swift`, subprocess spawning, secret environment handling, or tests that cover `exec` lifecycle/security behavior. |

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
12. Match the current package baseline in `Package.swift`: Swift tools 6.0 and `platforms: [.macOS(.v14)]`. Do not add compatibility shims or older deployment targets unless the user asks for them.
13. Keep library code responsible for throwing structured errors; centralize user-facing error translation in `Sources/bioenvLib/ErrorFormatting.swift` instead of formatting ad hoc messages across commands.
14. There is no formatter or linter config in this repo today. Preserve the existing style manually and do not add `swift-format`, SwiftLint, or similar tooling without explicit approval.
15. Prefer `struct`, `enum`, and static helpers for library code; only introduce reference types when a framework callback or shared mutable state truly requires one.
16. `Store.parseEnvFile` supports multiline quoted values (single or double), normalizes `\r\n`/`\r` to `\n`, strips UTF-8 BOM, and throws `EnvFileParseError` for unterminated quoted values. Invalid key names produce a stderr warning and are silently skipped (not a thrown error). Do not weaken or change this contract without updating `StoreTests.swift` and the `ErrorFormattingTests.swift` entry for `EnvFileParseError`. In contrast, `readSecrets` and `writeSecrets` call `validateSecretKeys` internally and throw `StoreError.invalidSecretKey` if the encrypted store contains a key that fails `[A-Za-z_][A-Za-z0-9_]*`; `main.swift` also checks `Store.isValidEnvVarName` for `set`/`get`/`remove` before touching the store. Keep these two validation paths (warn+skip for import, throw for store read/write) distinct and do not merge them.
17. Follow the naming style already used across the repo: types/files in UpperCamelCase, functions/properties/local bindings in lowerCamelCase, enum cases in lowerCamelCase, and command/config literals matching the shipped CLI strings exactly (`init`, `sync`, `appVersion`, etc.).
18. Prefer synchronous code paths by default. Only introduce `async`/`await`, actors, or detached tasks when an Apple framework API truly requires them, and keep Keychain/LocalAuthentication flows simple enough to stay warning-free under Swift 6 strict concurrency.
19. When CLI usage or aliases change, verify `README.md` against the actual `main.swift` help/usage text, including alternate invocation forms such as stdin-based `set`, `help` aliases, and `--version` aliases; do not assume the command table alone is sufficient documentation coverage.
20. Keep imports direct and file-local: import only the system frameworks and modules a file uses (`Foundation`, `CryptoKit`, `Security`, `LocalAuthentication`, `Darwin`, `bioenvLib`, `Testing`); do not introduce re-export/barrel modules or umbrella wrappers.
21. Preserve the `bioenv set KEY` stdin contract: read stdin to EOF, keep embedded newlines intact, and strip at most one trailing line ending (`\n` or `\r\n`) that shell pipelines append. Do not switch this path back to line-based reads or trim additional trailing whitespace without updating docs and tests.

## Testing

1. Run tests with `swift test`.
2. Tests live in `Tests/bioenvTests/`; use the Swift Testing framework (`@Suite`, `@Test`, `#expect`).
3. Test `bioenvLib` only — `main.swift` dispatch is not unit-tested.
4. Prefer mock-based Keychain and Touch ID unit tests by default. Keep any real Keychain integration coverage clearly marked and opt-in.
5. Use `FileManager.default.temporaryDirectory` + `UUID()` for temp files; always clean up with `defer { try? FileManager.default.removeItem(at: ...) }`.
6. Run `swift test` before every commit.
7. New public functions in `Store`, `Crypto`, or `Keychain` require corresponding tests.
8. Name test files by the production area they cover (`StoreTests.swift`, `CryptoTests.swift`, etc.) and group related assertions with `@Suite` blocks around one behavior or API surface.
9. Prefer regression tests for parsing, quoting, crypto, and error-reporting edge cases when fixing bugs; these have been the highest-churn areas in recent commits.
10. If you change user-visible failure wording or add a new error-mapping path, extend `Tests/bioenvTests/ErrorFormattingTests.swift` in the same change.
11. Skip unit tests for raw CLI usage/help text in `main.swift` unless that logic is first moved into `bioenvLib`.
12. Real Keychain integration tests are opt-in via `BIOENV_RUN_KEYCHAIN_INTEGRATION_TESTS=1`. Keep them isolated with unique synthetic project hashes and `defer` cleanup like `KeychainTests.swift`; never point a test at a real project path or persistent key name.
13. If you change `.env` parsing, invalid-key handling, or multiline quoting behavior, add regression tests that cover both the returned key/value data and any intentional stderr warning/skip behavior.
14. New public functions in `Exec` or changes to subprocess/environment behavior require matching coverage in `Tests/bioenvTests/ExecTests.swift`, including child exit status, parent-environment isolation, and secret-buffer scrubbing where relevant.
15. If you change `.githooks/pre-push`, `Package.swift`, or the contributor setup flow, run both `swift test` and `swift build` before commit so the checked-in hook contract remains accurate.
16. If you change stdin-based secret ingestion for `bioenv set KEY`, add or update regression coverage for multiline values and trailing newline normalization (`\n` and `\r\n`) so EOF-handling bugs do not regress silently.

## Architecture

1. All crypto operations go through `Crypto.swift` (CryptoKit AES-256-GCM only).
2. All Keychain access goes through `Keychain.swift` (Security + LocalAuthentication frameworks).
3. All encrypted-file I/O goes through `Store.swift`.
4. Config (`~/.bioenv/config.json`) is managed exclusively by `Config.swift`.
5. Never call `SecItem*` or `LAContext` directly from outside `Keychain.swift`.
6. Project identity is always the SHA-256 of the absolute directory path, first 16 hex chars. Do not change this scheme — it would break existing stores.
7. Environment-variable validation and shell escaping rules are centralized in `Store.swift`; do not duplicate export formatting or `.env` parsing logic in `main.swift` or tests.
8. Keep `main.swift` limited to argument dispatch, confirmation prompts, and stdout/stderr output. Reusable validation, file parsing, and stateful logic belong in `bioenvLib`.
9. Centralize user-facing error normalization in `ErrorFormatting.swift`; do not duplicate `NSError`, `DecodingError`, or `OSStatus` message mapping in commands or tests.
10. New shared production code belongs under `Sources/bioenvLib/`, and matching tests belong under `Tests/bioenvTests/` with a file name that matches the production concern.
11. Error types tightly coupled to a single module (e.g. `EnvFileParseError` in `Store.swift`) may be co-located in that module's file rather than in a separate file. Only extract to a dedicated file when the type is used across multiple modules.
12. `Store.parseEnvFile` is the only library method that writes a warning directly to stderr (for skipped invalid env key names). All other stderr output stays in `main.swift`. Do not add more stderr writes to library code; throw an error or return a result instead.
13. Preserve deterministic CLI output for secrets: commands like `load` and `list` must sort keys before printing, and tests should not rely on `Dictionary` iteration order.
14. Keep `status` low-friction for uninitialized projects: it may probe for store/key presence without authentication, but only prompt for Touch ID when actually decrypting secrets to count them.
15. All subprocess command parsing, environment merging, and process spawning go through `Sources/bioenvLib/Exec.swift`; do not call `Process`, `posix_spawn*`, or `waitpid` from `main.swift` or unrelated modules.
16. Treat `docs/superpowers/specs/2026-05-08-exec-command-security.md` as the design note for `bioenv exec`; when you change subprocess secret-handling or lifecycle semantics, update that spec in the same change.

## Dependency & Supply-Chain Security

1. This project intentionally has **zero external Swift Package dependencies**. Keep it that way.
2. Only Apple system frameworks are permitted: `Security`, `LocalAuthentication`, `CryptoKit`, `Foundation`.
3. If a new Swift package dependency is ever required, get explicit user approval, justify it in the commit message, and pin to a specific version tag in `Package.swift`.
4. Because there is no lockfile in this repo, treat any manifest change as supply-chain sensitive: do not add packages, build plugins, or generator tooling without explicit approval and a follow-up audit plan.
5. Do not add non-SwiftPM ecosystem manifests or installers (`package.json`, `Brewfile`, `Mintfile`, etc.) without explicit approval; this repo currently builds with SwiftPM and system tools only.
6. If a dependency exception is approved, inspect SwiftPM package plugins, macros, and any build-time code generation before adoption; treat them like executable code with the same review bar as a new binary.
7. If an external Swift package is ever approved, commit the generated `Package.resolved` in the same change and review the resolved identities/revisions before commit; do not leave dependency resolution implicit.
8. Before approving any external Swift package, inspect its `Package.swift` and repository for macros, plugins, build-tool execution, or generated-code hooks; treat SwiftPM build-time code like any other executable supply-chain risk.
9. Before adding a new package identity, verify it points to the intended upstream repository/owner and sane release history to reduce typosquatting or abandoned-fork risk; capture that check in the commit message or PR notes.
10. After any approved dependency change, run `swift package show-dependencies` and review the diff for `Package.swift` and `Package.resolved` together before commit.
11. If an exception is approved for any non-Swift ecosystem dependency or installer script, inspect its `postinstall`, `prepare`, build hook, and generated-binary behavior before running it; treat install-time scripts as arbitrary code execution.
12. After any approved dependency change outside SwiftPM, run the ecosystem-appropriate audit command (`npm audit`, `pnpm audit`, `cargo audit`, `pip-audit`, etc.) and record any blockers before commit.

## Scope & Safety Rules

1. Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`, `breaking:` prefixes.
2. Never bypass the pre-push hook (`--no-verify`). It runs `swift build` to catch compilation errors before they hit CI.
3. `Version.swift` (`appVersion`) is auto-overwritten by CI during release. Do not edit it manually or commit a non-`"dev"` value.
4. Release is triggered automatically on every push to `main` — ensure `swift test` and `swift build` pass before pushing.
5. The `destroy` command is irreversible (deletes Keychain key + encrypted store). Always describe the consequence and require explicit user confirmation before suggesting or running it.
6. Never commit `.env` files, `.env.local`, or any file containing real secrets.
7. Do not let documentation drift after CLI changes: if you add, remove, or rename a command or flag, update `README.md` and `CLAUDE.md` in the same change.
8. Do not run install-style commands (`make install`, manual `cp` into `~/bin`, or ad-hoc `codesign`) unless the user explicitly asked to change their local machine state.
9. Do not push to `main` or trigger a release-producing push without explicit user instruction; every push to `main` publishes automatically.
10. Use fake secret values in tests, examples, and docs edits. Never create, import, or echo a real credential while validating this repo.
11. Keep the checked-in contributor hook flow intact: if your change alters build verification expectations, update `.githooks/pre-push`, `README.md`, and the documented `make setup` workflow together instead of relying on undocumented local setup.
12. Work on a non-`main` branch by default. Do not create commits directly on `main` unless the user explicitly asked for that release-risky path.
13. Do not rewrite published history for this repo (`git push --force`, rebases that would require force-push, or branch deletion) without explicit user approval; `main` is release-producing and history edits are operationally sensitive.
