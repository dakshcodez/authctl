# Phase 1 — Foundation

This phase wires together everything the rest of the system depends on: configuration, logging, the database connection, and schema migrations. Nothing in this phase makes authentication decisions — it exists purely to give the upper layers a safe, validated environment to run in.

## Files

```
cmd/authctl/main.go
internal/config/
  config.go      — Config struct
  load.go        — reads env vars, parses durations/ints
  validate.go    — enforces invariants on the loaded config
internal/logger/
  logger.go      — slog wrapper with Audit() and Security() methods
internal/database/
  database.go    — Connect(): opens SQLite, sets PRAGMA, caps connections
  migrate.go     — Migrate(): runs embedded SQL migrations via golang-migrate
migrations/
  embed.go       — //go:embed *.sql bakes SQL files into the binary
  000001_create_users.up.sql
  000002_create_sessions.up.sql
```

## Startup sequence

`main.go` is the only wiring point in the application. It runs in a strict sequence — any step failing kills the process immediately:

```
PrintBanner()
  │
  ▼
config.Load()          ← reads env, parses types, validates values
  │ fail → os.Exit(1)
  ▼
logger.New(cfg)        ← selects text vs JSON handler based on APP_ENV
  │
  ▼
database.Connect()     ← opens SQLite, PRAGMA foreign_keys=ON, caps conns
  │ fail → os.Exit(1)
  ▼
database.Migrate()     ← runs pending SQL migrations from embedded FS
  │ fail → os.Exit(1)
  ▼
repository.New*()      ← wraps *sql.DB in typed repository structs
  │
  ▼
service.NewAuthService()
  │
  ▼
session.NewFileStore() ← file path derived from os.UserHomeDir()
  │
  ▼
readline setup + handler.Init() + shell.Run()
```

There is intentionally no retry logic and no graceful degradation. A misconfigured or missing database is a fatal condition.

## Config (`internal/config/`)

### Struct

```go
type Config struct {
    AppEnv            string
    LogLevel          string
    DBPath            string
    SessionTimeout    time.Duration
    MaxLoginAttempts  int
    LockoutDuration   time.Duration
    BcryptCost        int
    TOTPEncryptionKey []byte  // nil = MFA unavailable
}
```

Every field maps directly to a business requirement. There are no implementation-level knobs here (no pool sizes, no timeouts beyond session) — those are hardcoded where they are used.

### Load order

`load.go` calls `godotenv.Load()` silently (ignoring "file not found") before reading env vars. This means:

1. `.env` file is loaded if present
2. Real environment variables override `.env` values (OS env always wins)
3. Defaults are applied only when neither is set

### Validation (`validate.go`)

All validation runs **after** parsing, in one place, before any object is constructed. Checks include:

- `SessionTimeout > 0`
- `MaxLoginAttempts > 0`
- `LockoutDuration > 0`
- `BcryptCost` within `bcrypt.MinCost..bcrypt.MaxCost`
- `TOTPEncryptionKey` is exactly 0 or 32 bytes (0 = MFA disabled; anything else is a misconfiguration)

Failing validation returns an error before `main()` continues. There is no "best-effort startup with degraded MFA" — if the key is malformed, the process exits.

### Why env vars, not a config file?

Config files (YAML, TOML) require a parser, a schema, and a decision about where the file lives. Environment variables are the standard for containerised applications (12-factor), require no parser beyond the standard library, and map cleanly to Docker/compose secrets. The `.env` file is a developer convenience layered on top, not the canonical config source.

## Logger (`internal/logger/`)

A thin wrapper around `log/slog` that adds two domain-specific methods:

```go
func (l *Logger) Audit(msg string, args ...any)    // category=audit
func (l *Logger) Security(msg string, args ...any) // category=security
```

Both prepend `slog.String("category", "...")` to the args slice before calling the underlying logger. This makes audit and security events filterable without changing the log format.

### Format selection

| `APP_ENV` | Handler | Format |
|---|---|---|
| `production` | `slog.NewJSONHandler` | JSON (machine-readable, pipeable to log aggregators) |
| anything else | `slog.NewTextHandler` | Human-readable key=value |

### What the logger never does

- Logs passwords (even hashed)
- Logs session tokens (even hashed)
- Logs TOTP codes or secrets
- Logs user IDs in security events where the ID itself would reveal which usernames exist

The rule: if a log line could help an attacker who has read access to the logs, it does not get logged.

## Database (`internal/database/`)

### Connection (`database.go`)

`Connect()` does five things in order:

**1. Create the directory**
```go
os.MkdirAll(dir, 0700)
```
Mode `0700` means only the owner can read, write, or list the directory. Other users on the same machine cannot access the database file.

**2. Open the SQLite file**
```go
sql.Open("sqlite3", cfg.DBPath)
```
`sql.Open` does not actually connect — it returns a handle. The real connection is validated in the next step.

**3. Ping with a 5-second timeout**
Confirms the file is accessible and the driver is working before proceeding.

**4. Enable foreign keys**
```go
db.Exec("PRAGMA foreign_keys = ON;")
```
SQLite disables foreign key enforcement by default. This must be set per-connection. Since we use a single connection, setting it once is sufficient — but if the connection pool size were ever increased, each connection would need its own PRAGMA.

**5. Cap connections**
```go
db.SetMaxOpenConns(1)
db.SetMaxIdleConns(1)
db.SetConnMaxLifetime(0)
```
SQLite supports concurrent readers but only one writer at a time. Using a single connection eliminates write contention entirely — no "database is locked" errors. `ConnMaxLifetime(0)` means the connection lives forever and is never recycled.

### Migrations (`migrate.go`)

`Migrate()` uses `golang-migrate/migrate` with two adapters:

- **Source**: `iofs` — reads migration files from an `fs.FS` (in this case the embedded FS)
- **Driver**: `migrate_sqlite3` — wraps the existing `*sql.DB` handle

`migrate.ErrNoChange` is silently ignored. Every other error is fatal. The migrator creates a `schema_migrations` table in SQLite to track which migrations have run.

## Embedded migrations (`migrations/`)

```go
// migrations/embed.go
//go:embed *.sql
var FS embed.FS
```

The `//go:embed` directive bakes every `.sql` file in the directory into the compiled binary at build time. The binary carries its own schema — it can be deployed to any machine and the database will be created correctly without copying migration files alongside it.

### Schema design decisions

**`users` table**

```sql
mfa_enabled  INTEGER NOT NULL DEFAULT 0 CHECK (mfa_enabled IN (0, 1))
```
SQLite has no boolean type. `INTEGER` with a CHECK constraint enforces the 0/1 invariant at the database level, not just in Go.

```sql
failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0)
```
Prevents a bug from driving the counter negative, which could bypass the lockout check.

```sql
encrypted_totp_secret TEXT  -- nullable
```
Nullable because TOTP is optional. A `NULL` here means MFA is not set up, which is distinct from MFA being disabled after being set up.

**`sessions` table**

```sql
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
```
Deleting a user automatically removes all their sessions. No orphaned session rows.

```sql
CREATE INDEX idx_sessions_user_active ON sessions(user_id, is_active);
```
The most common session query is "find active session for user". The composite index on `(user_id, is_active)` makes this O(log n) instead of a full scan.

## Connection between phases

- **Phase 2** (Repository) receives the `*sql.DB` from `Connect()` and wraps it in typed repositories.
- **Phase 3** (Service) receives `*Config` for bcrypt cost, session timeout, lockout settings, and the TOTP encryption key.
- **Phase 6** (MFA) validates that `TOTPEncryptionKey` is set before allowing any MFA operation.
- **Phase 7** (Docker) mounts a volume at the DB path so the SQLite file persists across container restarts.
