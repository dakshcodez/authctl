# Phase 3 — Service Layer

The service layer owns all business logic. It sits between the CLI and the repository, making decisions that neither layer should make: when to lock an account, how to handle timing, what constitutes a valid session.

## Files

```
internal/service/
  auth.go       — AuthService interface, error sentinels, result types
  auth_impl.go  — authService implementation
  crypto.go     — AES-256-GCM helpers for TOTP secrets
  auth_test.go  — unit tests using fake repositories
  crypto_test.go
  fakes_test.go — in-memory fakes implementing repository interfaces
  mfa_test.go
```

## Interface

```go
type AuthService interface {
    Register(ctx context.Context, username, password string) (*models.User, error)
    Login(ctx context.Context, username, password string) (*LoginResult, error)
    LoginWithMFA(ctx context.Context, username, password, code string) (*LoginResult, error)
    Logout(ctx context.Context, token string) error
    ValidateSession(ctx context.Context, token string) (*models.User, error)
    SetupMFA(ctx context.Context, userID string) (*MFASetupResult, error)
    VerifyAndEnableMFA(ctx context.Context, userID, code string) error
    DisableMFA(ctx context.Context, userID, code string) error
    VerifyMFALogin(ctx context.Context, userID, code string) error
}
```

The service layer never calls `database/sql` directly. It holds `repository.UserRepository` and `repository.SessionRepository` interfaces, not concrete types. This keeps the test seam clean.

## Error sentinels

```go
var (
    ErrInvalidCredentials = errors.New("invalid username or password")
    ErrAccountLocked      = errors.New("account temporarily locked")
    ErrUserExists         = errors.New("username already taken")
    ErrSessionNotFound    = errors.New("session not found or expired")
    ErrMFARequired        = errors.New("MFA code required")
    ErrInvalidMFACode     = errors.New("invalid MFA code")
    ErrMFANotEnabled      = errors.New("MFA is not enabled on this account")
    ErrMFAAlreadyEnabled  = errors.New("MFA is already enabled on this account")
    ErrTOTPNotConfigured  = errors.New("TOTP secret not yet configured — run 'mfa setup' first")
    ErrMFAUnavailable     = errors.New("MFA is unavailable — TOTP_ENCRYPTION_KEY not configured")
)
```

All errors are sentinel values. Callers use `errors.Is`, never string comparison. The CLI layer maps these to user-facing messages in `userMessage()`.

## Registration

```go
func (s *authService) Register(ctx context.Context, username, password string) (*models.User, error)
```

1. bcrypt the password at the configured cost
2. Build a `*models.User` with a new UUID
3. Call `users.Create` — if it fails (UNIQUE constraint on username), return `ErrUserExists`
4. Log `category=audit`
5. Return the user (caller does not get the password hash back — it's inside the returned struct but the CLI doesn't display it)

Password validation (minimum length) happens in the CLI before this is called.

## Login and timing attack prevention

```go
func (s *authService) Login(ctx context.Context, username, password string) (*LoginResult, error)
```

When a username is not found, a real bcrypt comparison still runs:

```go
bcrypt.CompareHashAndPassword(
    []byte("$2a$12$dummyhashfortimingnoop00000000000000000000000000000000"),
    []byte(password),
)
```

Without this, an attacker can distinguish "wrong username" (fast response) from "wrong password" (slow response due to bcrypt). The dummy hash ensures both paths take the same time. `ErrInvalidCredentials` is returned for both cases — the same error, same message.

### LoginResult and the user snapshot

```go
type LoginResult struct {
    Session *models.Session
    User    *models.User
}
```

`Login` captures `userSnapshot := *user` **before** calling `UpdateLastLogin`. The returned `User` therefore holds the _previous_ login time. The CLI shows "Last login: <previous time>" — the same behaviour as `ssh`. If the snapshot were taken after the update, the displayed time would always be "just now".

## Account lockout

```go
func (s *authService) handleFailedAttempt(ctx context.Context, user *models.User)
```

Called on every bcrypt failure:

1. `IncrementFailedAttempts` — increments the counter and records the time
2. If `failedAttempts + 1 >= cfg.MaxLoginAttempts`, call `LockUntil(now + cfg.LockoutDuration)`
3. Log `category=security`

The lockout check happens at the start of `Login`, before bcrypt, so locked accounts fail immediately without running bcrypt.

`ResetFailedAttempts` is called on every successful login, clearing the counter and removing any active lock.

## Session token generation

```go
func generateToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}
```

32 bytes from `crypto/rand` = 256 bits of entropy. Hex-encoded to 64 characters for storage. The repository hashes this before writing to the database.

## Session validation

```go
func (s *authService) ValidateSession(ctx context.Context, token string) (*models.User, error)
```

1. Look up session by token hash
2. Call `session.IsValid()` — must be both active and not expired
3. Look up the user by `session.UserID`
4. Return the user

The CLI calls this on `whoami` and on every `mfa` command to verify the session is still valid before making changes.

## MFA login (two-step, no intermediate state)

When `Login` returns `ErrMFARequired`, the CLI prompts for a TOTP code and calls `LoginWithMFA`:

```go
func (s *authService) LoginWithMFA(ctx context.Context, username, password, code string) (*LoginResult, error)
```

This re-verifies credentials **and** the TOTP code in a single call:

1. Look up the user by username (dummy bcrypt if not found)
2. Check lockout
3. Run bcrypt on the password again
4. Decrypt the TOTP secret with AES-256-GCM
5. Validate the TOTP code
6. Create session + update last login

The password is verified twice (once in `Login`, once in `LoginWithMFA`). This is intentional — there is no intermediate state stored between the two prompts. The alternative (storing a half-authenticated state) would introduce a window where an attacker could skip the TOTP step by replaying the first-factor result.

## Testing

Tests use in-memory fakes in `fakes_test.go`:

```go
type fakeUserRepo struct {
    byUsername map[string]*models.User
    byID       map[string]*models.User
}
```

The fakes implement the full `UserRepository` and `SessionRepository` interfaces. Tests exercise the service logic without any SQLite. This is the right seam — repository correctness is tested in `internal/repository/`, service correctness is tested here.

The MFA tests use `github.com/pquerna/otp/totp.GenerateCode` to produce valid TOTP codes for the current 30-second window during test execution. This avoids hardcoding codes that expire.
