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
swift build -c release
codesign -s - -f .build/release/bioenv
cp .build/release/bioenv ~/bin/
```

## File Structure

```
Sources/bioenv/
  main.swift       # CLI entry, argument parsing, command dispatch
  Keychain.swift   # Keychain CRUD + Touch ID auth via LAContext (Security + LocalAuthentication frameworks)
  Crypto.swift     # AES-256-GCM encrypt/decrypt (CryptoKit)
  Store.swift      # Encrypted JSON file operations, .env parsing, shell escaping
  Config.swift     # Configuration management (~/.bioenv/config.json)
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
bioenv config            # Show current configuration
bioenv config sync on|off  # Enable/disable iCloud Keychain sync (default: off, requires Apple Developer cert)
```

## direnv Integration

`.envrc`:
```bash
eval "$(bioenv load)"
```

## Design Spec

Full design: `docs/superpowers/specs/2026-03-26-bioenv-design.md`
