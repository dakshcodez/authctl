# Phase 6 — MFA / TOTP

TOTP-based MFA layered on top of password authentication. Every design decision prioritises what happens if the database is breached or the key is lost.

## Files

```
internal/service/
  crypto.go       — encryptTOTPSecret / decryptTOTPSecret (AES-256-GCM)
  crypto_test.go
  auth_impl.go    — SetupMFA, VerifyAndEnableMFA, DisableMFA, LoginWithMFA
  mfa_test.go     — 9 tests for the full MFA lifecycle
internal/repository/
  user.go         — StoreTOTPSecret, ActivateMFA, DisableMFA
internal/cli/
  handler.go      — mfa, mfaSetup, mfaEnable, mfaDisable commands
```

## TOTP secret encryption

TOTP secrets are stored encrypted in the database. The encryption key lives outside the database in `TOTP_ENCRYPTION_KEY`. A database breach alone cannot recover TOTP secrets.

### AES-256-GCM

```go
func encryptTOTPSecret(key []byte, plaintext string) (string, error) {
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize()) // 12 bytes
    io.ReadFull(rand.Reader, nonce)
    sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.StdEncoding.EncodeToString(sealed), nil
}
```

Wire format stored in SQLite: `base64(12-byte nonce || ciphertext || 16-byte GCM authentication tag)`

`gcm.Seal(nonce, nonce, plaintext, nil)` prepends the nonce to the ciphertext in one allocation. The result is `nonce || ciphertext || tag`.

**Why a random nonce per call?** Two users with the same TOTP secret (unlikely but possible) produce different ciphertexts. More importantly, if an attacker ever sees two encryptions of the same value under the same key, they cannot use nonce-reuse attacks to recover the key. GCM is catastrophically broken on nonce reuse — the random nonce prevents this structurally.

**Why AES-256-GCM?**
- 256-bit key: forward-secure against brute-force
- GCM: authenticated encryption — decryption fails if the ciphertext or nonce is tampered with (the 16-byte tag covers both). An attacker cannot flip bits in the ciphertext and get silently wrong output.
- Standard library: `crypto/aes` + `crypto/cipher`. No third-party crypto dependency.

### Decryption

```go
func decryptTOTPSecret(key []byte, encoded string) (string, error) {
    data, _ := base64.StdEncoding.DecodeString(encoded)
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", errors.New("decryption failed — wrong key or corrupted data")
    }
    return string(plaintext), nil
}
```

`gcm.Open` returns an error if the GCM tag does not match. This detects both wrong keys and corrupted data. The error message deliberately does not distinguish between the two — callers should not know which condition occurred.

## The `TOTP_ENCRYPTION_KEY`

- Must be exactly 32 bytes (64 hex chars) when set
- `nil` means MFA is unavailable — all MFA service methods return `ErrMFAUnavailable` immediately
- Lives in the `.env` file and is loaded into `config.Config.TOTPEncryptionKey`
- Validated at startup — malformed keys are a fatal error, not a warning

**What happens if the key is lost?** All stored TOTP secrets become unrecoverable. Users must re-enrol MFA. The key must be backed up securely and separately from the database.

## MFA lifecycle

### Setup — three-step process

```
mfa setup
  → service.SetupMFA()
      → totp.Generate(Issuer=authctl, AccountName=username)
      → encryptTOTPSecret(key, secret)
      → repo.StoreTOTPSecret(userID, encrypted)   ← mfa_enabled stays 0
  → CLI renders QR code + manual secret key

mfa enable <code>
  → service.VerifyAndEnableMFA(userID, code)
      → decryptTOTPSecret → totp.Validate(code, secret)
      → repo.ActivateMFA(userID)                  ← mfa_enabled = 1

  (from this point, login requires TOTP)

mfa disable <code>
  → service.DisableMFA(userID, code)
      → decryptTOTPSecret → totp.Validate(code, secret)
      → repo.DisableMFA(userID)                   ← mfa_enabled = 0, secret = NULL
```

The secret is stored (`StoreTOTPSecret`) before MFA is activated. This allows the user to scan the QR code, confirm their authenticator app works by entering a code (`VerifyAndEnableMFA`), and only then activate MFA. If setup is interrupted between `mfa setup` and `mfa enable`, MFA remains off and the stored secret is inert.

Disable requires a valid TOTP code. An attacker who has physical access to the machine but not the authenticator device cannot disable MFA.

### Login with MFA

```
login alice
  → service.Login() → ErrMFARequired (password correct, MFA on)
  → CLI prompts: "TOTP code: "
  → service.LoginWithMFA(username, password, code)
      → re-verify credentials (bcrypt again)
      → decryptTOTPSecret → totp.Validate(code, secret)
      → createSession + UpdateLastLogin
```

`LoginWithMFA` re-verifies both factors in one call. The password is checked twice (once in `Login`, once in `LoginWithMFA`). This eliminates any intermediate authenticated state — there is no half-logged-in condition in the database or in memory.

## QR code rendering

```go
qrterminal.GenerateWithConfig(result.ProviderURI, qrterminal.Config{
    Level:      qrterminal.L,
    Writer:     h.out,
    HalfBlocks: true,
    BlackChar:  qrterminal.BLACK_BLACK,
    WhiteChar:  qrterminal.WHITE_WHITE,
})
```

`HalfBlocks: true` uses Unicode half-block characters (`▀`, `▄`) to render two rows of QR modules per terminal line, producing a compact QR code that most authenticator apps can scan directly from the terminal.

`ProviderURI` is an `otpauth://` URI in the standard format: `otpauth://totp/authctl:username?secret=BASE32&issuer=authctl`. Authenticator apps that scan QR codes expect this format.

A manual key fallback is always displayed below the QR code for environments where the QR code cannot be scanned.

## `pquerna/otp`

`github.com/pquerna/otp` v1.5.0 handles TOTP key generation and code validation:

- `totp.Generate(opts)` — generates a new TOTP key with a Base32 secret, configures the OTP URI
- `totp.Validate(code, secret)` — validates a 6-digit code against the current 30-second window (accepts ±1 window for clock skew)

TOTP codes are time-based (RFC 6238). The standard window tolerance (±1 × 30 seconds = ±30 seconds) is enough for most clock skew. No custom window extension is applied.

## What MFA does not protect against

- The plaintext session token is stored in `~/.authctl/session`. If an attacker reads this file, they can use the session until it expires. MFA is a second factor at login, not at every command.
- If the `TOTP_ENCRYPTION_KEY` is compromised alongside the database, all TOTP secrets are recoverable.
- The 30-second TOTP window means a stolen code is valid for up to 60 seconds after it is observed (current window + previous window tolerance).

These are documented trade-offs inherent to TOTP-based MFA, not implementation bugs.
