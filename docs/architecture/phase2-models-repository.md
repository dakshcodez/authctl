# Phase 2 — Models & Repository

This phase defines the data types the application works with and draws a hard boundary around all SQL. Nothing above the repository layer ever touches `database/sql`.

## Files

```
internal/models/
  user.go           — User struct + IsLocked()
  session.go        — Session struct + IsExpired() + IsValid()
internal/repository/
  user.go           — UserRepository interface + sqliteUserRepository
  session.go        — SessionRepository interface + sqliteSessionRepository
  user_test.go      — integration tests against :memory: SQLite
  session_test.go   — integration tests against :memory: SQLite
  testhelper_test.go — schema setup shared by tests
```

## Models (`internal/models/`)

Models are plain Go structs. No database tags, no methods beyond domain logic, no ORM references.

### `User`

```go
type User struct {
    ID                  string
    Username            string
    PasswordHash        string
    MFAEnabled          bool
    EncryptedTOTPSecret *string    // nil = not set up
    FailedAttempts      int
    LastFailedAt        *time.Time
    LockedUntil         *time.Time
    RegisteredAt        time.Time
    LastLoginAt         *time.Time
}

func (u *User) IsLocked() bool {
    return u.LockedUntil != nil && u.LockedUntil.After(time.Now())
}
```

`IsLocked()` is the only method on `User`. It encodes a domain invariant — a locked account is one with a future `LockedUntil` — so callers don't repeat this logic.

Nullable fields use pointer types (`*string`, `*time.Time`) rather than `sql.NullString` / `sql.NullTime`. The repository layer handles the SQL-to-Go mapping. The model stays clean of `database/sql` imports.

### `Session`

```go
type Session struct {
    ID        string
    UserID    string
    Token     string
    CreatedAt time.Time
    ExpiresAt time.Time
    IsActive  bool
}

func (s *Session) IsExpired() bool { return time.Now().After(s.ExpiresAt) }
func (s *Session) IsValid() bool   { return s.IsActive && !s.IsExpired() }
```

`Token` on a returned `*Session` holds the **SHA-256 hash** of the original token, not the plaintext. This is set by the repository when scanning a row. Callers must never compare `Session.Token` against a raw token string.

## Repository layer

### The invariant

**All SQL lives in `internal/repository/`. Nowhere else.**

The service layer, CLI, and tests outside this package never call `database/sql` directly. This makes it possible to reason about all database interactions from one place, and to swap the storage backend without touching business logic.

### `ErrNotFound`

```go
var ErrNotFound = errors.New("not found")
```

The single sentinel for "row does not exist". Callers use `errors.Is(err, repository.ErrNotFound)` — never string comparison. Both repositories translate `sql.ErrNoRows` into `ErrNotFound` before returning.

### `UserRepository` interface

```go
type UserRepository interface {
    Create(ctx context.Context, user *models.User) error
    GetByUsername(ctx context.Context, username string) (*models.User, error)
    GetByID(ctx context.Context, id string) (*models.User, error)
    IncrementFailedAttempts(ctx context.Context, id string, at time.Time) error
    LockUntil(ctx context.Context, id string, until time.Time) error
    ResetFailedAttempts(ctx context.Context, id string) error
    UpdateLastLogin(ctx context.Context, id string, at time.Time) error
    EnableMFA(ctx context.Context, id string, encryptedSecret string) error
    StoreTOTPSecret(ctx context.Context, id string, encryptedSecret string) error
    ActivateMFA(ctx context.Context, id string) error
    DisableMFA(ctx context.Context, id string) error
}
```

Every method takes `context.Context` first. No exceptions. This allows the caller to propagate deadlines and cancellation.

#### MFA operation split

TOTP setup is intentionally split into two separate repository calls:

| Method | What it does | When called |
|---|---|---|
| `StoreTOTPSecret` | Writes `encrypted_totp_secret`, leaves `mfa_enabled=0` | `mfa setup` |
| `ActivateMFA` | Sets `mfa_enabled=1` without changing the secret | `mfa enable <code>` |
| `DisableMFA` | Sets `mfa_enabled=0`, clears `encrypted_totp_secret` | `mfa disable <code>` |

This allows the user to generate a secret, scan the QR code, and verify a code before MFA is actually active. If the setup is interrupted, MFA remains off.

### `SessionRepository` interface

```go
type SessionRepository interface {
    Create(ctx context.Context, session *models.Session) error
    GetByToken(ctx context.Context, token string) (*models.Session, error)
    Invalidate(ctx context.Context, id string) error
    InvalidateAllForUser(ctx context.Context, userID string) error
    DeleteExpired(ctx context.Context) error
}
```

### Token hashing

```go
func hashToken(token string) string {
    h := sha256.Sum256([]byte(token))
    return hex.EncodeToString(h[:])
}
```

`Create` calls `hashToken` before inserting. `GetByToken` calls `hashToken` before querying. The plaintext token is never written to the database. A full database dump cannot replay any session.

SHA-256 (rather than bcrypt) is appropriate here because session tokens are 32 bytes of `crypto/rand` output — they have ~256 bits of entropy, making preimage attacks infeasible without the computational expense of bcrypt.

### `execExpectOne`

```go
func execExpectOne(ctx context.Context, db *sql.DB, query string, args ...any) error {
    res, err := db.ExecContext(ctx, query, args...)
    // ...
    if n == 0 {
        return ErrNotFound
    }
    return nil
}
```

All `UPDATE` and `DELETE` calls go through this helper. If zero rows are affected (the target ID does not exist), it returns `ErrNotFound` rather than silently succeeding. This prevents silent no-ops when the service calls an update on a deleted account.

### SQLite type mapping

SQLite has no boolean type. The `boolToInt` helper converts `bool → 0/1` for writes. On reads, the repository converts back:

```go
u.MFAEnabled = mfaEnabled == 1
s.IsActive = isActive == 1
```

Nullable SQL fields map to `sql.NullString` / `sql.NullTime` in the scan step, then to `*string` / `*time.Time` on the model:

```go
var lockedUntil sql.NullTime
// ... row.Scan(...)
if lockedUntil.Valid {
    u.LockedUntil = &lockedUntil.Time
}
```

## Testing

Tests use real in-memory SQLite, not mocks:

```go
// testhelper_test.go
func newTestDB(t *testing.T) *sql.DB {
    db, _ := sql.Open("sqlite3", ":memory:")
    db.Exec("PRAGMA foreign_keys = ON")
    // ... CREATE TABLE statements ...
    return db
}
```

No mocks. The repository layer is too close to SQL to test meaningfully without hitting real SQL. Mocked tests here would only verify that `ExecContext` was called — not that the query is correct or the schema matches.

Tests cover:
- `Create` then `GetByUsername` round-trip
- `GetByUsername` on a non-existent user → `ErrNotFound`
- `IncrementFailedAttempts` + `LockUntil` → `IsLocked()` returns true
- `ResetFailedAttempts` clears lock
- Session `Create` + `GetByToken` with hash verification
- `Invalidate` → `IsValid()` returns false
- `DeleteExpired` removes stale sessions only
