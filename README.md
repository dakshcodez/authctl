# authctl

A containerised CLI authentication system with TOTP-based MFA. Built in Go with SQLite, bcrypt, and AES-256-GCM encryption.

## Features

- Interactive readline shell with history and tab completion
- User registration with bcrypt password hashing (cost 12)
- Account lockout after configurable failed attempts
- Session management with cryptographically random tokens (SHA-256 hashed in DB)
- TOTP-based MFA (RFC 6238) with AES-256-GCM encrypted secrets at rest
- Audit and security event logging via `log/slog`
- Single-binary, zero runtime dependencies beyond the SQLite file

## Quick start

### Docker (recommended)

```sh
# Generate a TOTP encryption key (required for MFA)
export TOTP_ENCRYPTION_KEY=$(openssl rand -hex 32)

# Start the shell
docker compose run --rm authctl
```

### Local build

Requires Go 1.25+ and a C compiler (for CGO/sqlite3).

```sh
go build -o authctl ./cmd/authctl
./authctl
```

## Shell commands

```
register [username]    Create a new account
login [username]       Log in (prompts for TOTP code when MFA is enabled)
logout                 End the current session
whoami                 Show session and account details
mfa setup              Generate a TOTP secret and display it for your authenticator app
mfa enable <code>      Verify the first code and activate MFA
mfa disable <code>     Deactivate MFA (requires a valid TOTP code)
help                   Show this list
exit                   Quit
```

## MFA setup flow

```
authctl(alice)> mfa setup
  Secret key: JBSWY3DPEHPK3PXP
  Add this to your authenticator app then run: mfa enable <code>

authctl(alice)> mfa enable 123456
✓ MFA enabled. Your account now requires a TOTP code at login.
```

Future logins:

```
authctl> login alice
Password:
MFA is enabled on this account.
TOTP code: 123456
╔ Login Successful ...
```

## Configuration

All settings are environment variables. Defaults are safe for local use.

| Variable               | Default                 | Description                                |
|------------------------|-------------------------|--------------------------------------------|
| `APP_ENV`              | `development`           | `development` or `production`              |
| `LOG_LEVEL`            | `info`                  | `debug`, `info`, `warn`, `error`           |
| `DB_PATH`              | `~/.authctl/authctl.db` | SQLite file path                           |
| `SESSION_TIMEOUT`      | `24h`                   | Session validity duration                  |
| `MAX_LOGIN_ATTEMPTS`   | `5`                     | Failed attempts before lockout             |
| `LOCKOUT_DURATION`     | `15m`                   | How long an account stays locked           |
| `BCRYPT_COST`          | `12`                    | bcrypt work factor (min 4, max 31)         |
| `TOTP_ENCRYPTION_KEY`  | _(unset)_               | 64 hex chars (32 bytes). Required for MFA. |

Generate a key: `openssl rand -hex 32`

## Security design

- Passwords are never stored; only bcrypt hashes.
- Session tokens are 32 random bytes (hex-encoded). Only a SHA-256 hash is stored in the database — a full DB dump cannot replay sessions.
- TOTP secrets are encrypted with AES-256-GCM before storage. The nonce is random per encryption so identical secrets produce different ciphertexts.
- Failed login attempts trigger an account lockout. Timing is equalised for unknown usernames to prevent enumeration.
- The SQLite database directory is created with mode 0700; the session file is written with mode 0600.
- Database migrations run automatically at startup; foreign keys are enforced.

## Development

```sh
# Run all tests
go test ./...

# Run a single package
go test ./internal/service/...

# Build
go build ./cmd/authctl
```

Tests use real in-memory SQLite (`:memory:`) — no mocks for the database layer.
