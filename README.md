# bioenv

Biometric-protected environment variables for macOS. Touch ID before your secrets are revealed.

Replace plaintext `.env` files with encrypted storage. One fingerprint tap to load secrets into your shell.

## Install

**Option 1: Download pre-built binary (easiest)**

```bash
curl -L https://github.com/3h4x/bioenv/releases/latest/download/bioenv-arm64 -o ~/bin/bioenv
chmod +x ~/bin/bioenv
codesign -s - -f ~/bin/bioenv
```

Or, from a clone of this repo:

```bash
make install   # downloads latest release binary to ~/bin and signs it
```

**Option 2: Build from source**

Requires macOS with Xcode or Command Line Tools.

```bash
git clone https://github.com/3h4x/bioenv.git
cd bioenv
make install-from-source  # builds, signs, and copies to ~/bin
make setup                # activates pre-push hook (optional, for contributors)
```

Make sure `~/bin` is in your `PATH`.

## Quick Start

```bash
# 1. Go to your project
cd ~/workspace/my-app

# 2. Initialize bioenv (creates an encryption key for this project)
bioenv init

# 3. Add your secrets (Touch ID prompt)
bioenv set DATABASE_URL "postgres://user:pass@localhost/mydb"
bioenv set API_KEY "sk-abc123"
bioenv set STRIPE_SECRET "whsec_..."

# 4. Use them
eval "$(bioenv load)"    # exports all secrets into current shell
bioenv exec -- env       # injects secrets into one subprocess only
bioenv get API_KEY       # print a single value
```

That's it. Your secrets are encrypted at rest, and Touch ID is required every time you access them.

## Migrating from .env.local

Stop keeping secrets in plaintext. Here's how to migrate an existing project:

```bash
cd ~/workspace/my-app

# 1. Initialize bioenv for this project
bioenv init

# 2. Import all secrets from your .env.local
bioenv import .env.local

# 3. Verify everything was imported
bioenv list                    # check all keys are there
bioenv get DATABASE_URL        # spot-check a value

# 4. Set up direnv to load from bioenv instead
#    Replace the contents of .envrc with:
echo 'eval "$(bioenv load)"' > .envrc
direnv allow

# 5. Test it — cd out and back in, confirm your app still works
cd .. && cd my-app
env | grep DATABASE_URL        # should show your secret

# 6. Once confirmed, delete the plaintext file
rm .env.local
```

Your secrets are now encrypted. The `.env.local` file is gone, but everything works exactly the same — direnv still loads your env vars automatically, the only difference is a Touch ID prompt.

This also works with `.env`, `.env.development`, or any file in `KEY=VALUE` format.

**`.env` parsing rules:**
- Keys must match `[A-Za-z_][A-Za-z0-9_]*` (POSIX env var names). Invalid keys are warned and skipped.
- Both single and double-quoted values are supported; physical multi-line quoted values preserve embedded newlines.
- Backslash sequences inside quoted values are **stored verbatim** — `\"` stays as `\"`, `\n` stays as `\n` (two characters). bioenv does not interpret escape sequences on import; what you import is what you get.
- Unquoted values strip trailing inline comments (`value # comment` → `value`).
- Unterminated quoted values fail with a line-specific error instead of importing partial data.

## direnv Integration

The real power is automatic loading. Add `eval "$(bioenv load)"` to your project's `.envrc`:

```bash
# Non-secret env vars stay in .envrc as usual
export SUPABASE_TYPE=local
export NODE_OPTIONS="--max-old-space-size=8192"

# Secrets loaded from bioenv (Touch ID prompt)
eval "$(bioenv load)"
```

Now when you `cd` into the project, direnv triggers `bioenv load`, Touch ID prompts once, and all secrets are loaded into your shell session. Leave the directory and they're gone.

**Important:** Remove any `dotenv .env.local` lines from `.envrc` after migrating — the file no longer exists and direnv will warn about it on every load.

## All Commands

| Command | Touch ID | Description |
|---------|----------|-------------|
| `bioenv init` | No | Set up bioenv for the current directory |
| `bioenv set KEY VALUE` | Yes | Add or update a secret |
| `bioenv set KEY` | Yes | Add or update a secret from stdin (reads until EOF; strips one trailing newline) |
| `bioenv get KEY` | Yes | Print a single secret value |
| `bioenv load` | Yes | Print `export KEY=VALUE` for all secrets |
| `bioenv exec -- COMMAND [ARGS...]` | Yes | Run one command with project secrets injected into its environment |
| `bioenv import FILE` | Yes | Bulk import from a `.env` file |
| `bioenv list` | Yes | List secret names (no values) |
| `bioenv remove KEY` | Yes | Delete a secret (aliases: `rm`, `del`) |
| `bioenv status` | Conditional | Show status for the current directory and prompt only if counting secrets |
| `bioenv destroy` | No | Delete the Keychain key and encrypted store after explicit confirmation |
| `bioenv config` | No | Show current configuration |
| `bioenv config sync on\|off\|true\|false\|yes\|no` | No | Toggle iCloud Keychain sync (default: off) |
| `bioenv version` | No | Show installed version |
| `bioenv --version` | No | Alias for `version` |
| `bioenv help`, `bioenv --help`, `bioenv -h` | No | Show usage text |

## How It Works

Each project directory gets its own encryption key and encrypted store:

```
~/workspace/my-app/     -->  key in Keychain: "com.bioenv.a1b2c3d4..."
                         -->  secrets in:     ~/.bioenv/a1b2c3d4....enc
```

1. `bioenv init` generates an AES-256 key, stores it in macOS Keychain, and creates an empty encrypted file
2. Project identity = SHA-256 of the absolute directory path (so each project is isolated)
3. Secrets are stored as AES-256-GCM encrypted JSON
4. Commands that decrypt or modify secrets require Touch ID (or system password) before the encryption key is used
5. `bioenv load` outputs shell `export` statements — designed for `eval "$(bioenv load)"`
6. `bioenv exec -- ...` spawns a child process with a temporary environment containing the project secrets, leaving the parent shell untouched

## Configuration

Config is stored at `~/.bioenv/config.json`.

```bash
bioenv config              # show current settings
bioenv config sync off     # keys stay on this Mac only (default)
bioenv config sync on      # sync keys via iCloud Keychain (requires Apple Developer cert)
bioenv config sync yes     # alias for `on`
bioenv config sync no      # alias for `off`
```

**Sync note:** iCloud Keychain sync requires the binary to be signed with an Apple Developer certificate ($99/yr). With ad-hoc signing (the default), keys are device-only. If you get a new Mac, you'll need to re-import your secrets. Keep your `.env` files in a password manager as the source of truth.

## Security

- AES-256-GCM encryption (authenticated, tamper-proof)
- Encryption keys stored in macOS Keychain, device-bound by default
- Touch ID or system password required before any secret access
- Secrets never written to disk in plaintext (after initial import)
- Encrypted files are safe to backup — useless without this Mac's Keychain
- No master password, no config files, no subscriptions
- Ad-hoc code signing works (no Apple Developer account needed)

## Limitations

- macOS only (requires Keychain + LocalAuthentication framework)
- Keys are tied to the device by default — not portable across machines
- iCloud Keychain sync requires Apple Developer certificate
- No team sharing (use Vault/1Password for that)

## License

MIT
