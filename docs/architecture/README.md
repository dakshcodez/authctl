# Architecture Overview

authctl is a containerised CLI authentication system. Every design decision starts from one question: **what is the minimum attack surface that still delivers the required functionality?**

## System architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                           │
│   Shell (readline) → Handler → Prompter → userinfo/style   │
└─────────────────────────┬───────────────────────────────────┘
                          │ calls
┌─────────────────────────▼───────────────────────────────────┐
│                      Service Layer                          │
│         AuthService → crypto helpers → TOTP (MFA)          │
└──────────────┬──────────────────────┬───────────────────────┘
               │ reads/writes         │ reads/writes
┌──────────────▼──────┐   ┌───────────▼─────────────────────┐
│  UserRepository     │   │  SessionRepository               │
│  (SQL boundary)     │   │  (SQL boundary, token hashing)   │
└──────────────┬──────┘   └───────────┬─────────────────────┘
               │                      │
┌──────────────▼──────────────────────▼───────────────────────┐
│                     SQLite (single connection)               │
│              migrations embedded in binary                   │
└─────────────────────────────────────────────────────────────┘

Orthogonal:
  Config  → loaded from env vars on startup, validated immediately
  Logger  → slog wrapper, writes audit + security category events
  Session Store → file on disk (~/.authctl/session), CLI convenience only
```

## Layer responsibilities

| Layer | Package | Rule |
|---|---|---|
| Entry point | `cmd/authctl` | Wires everything together. No business logic. |
| Config | `internal/config` | Loads and validates all env vars. Fails fast on bad config. |
| Logger | `internal/logger` | Structured logging. Never logs secrets. |
| Database | `internal/database` | Opens SQLite, runs migrations. One connection. |
| Models | `internal/models` | Plain structs. No DB tags, no methods beyond domain logic. |
| Repository | `internal/repository` | **All SQL lives here.** No SQL anywhere else. |
| Service | `internal/service` | **All business logic lives here.** No SQL, no HTTP. |
| Session store | `internal/session` | File-based CLI session cache. Not the auth source of truth. |
| CLI | `internal/cli` | Renders output, reads input, dispatches to service. No business logic. |
| Migrations | `migrations` | SQL files embedded in the binary. Versioned. |

## Phase docs

| Phase | What it covers |
|---|---|
| [Phase 1 — Foundation](phase1-foundation.md) | Config, logger, database, migrations, main wiring |
| [Phase 2 — Models & Repository](phase2-models-repository.md) | Structs, SQL layer, token hashing, tests |
| [Phase 3 — Service Layer](phase3-service.md) | Auth business logic, lockout, timing attack defence |
| [Phase 4 — Session Store](phase4-session.md) | File-based CLI session, permissions, expiry |
| [Phase 5 — CLI](phase5-cli.md) | readline shell, handler dispatch, UX, interrupt handling |
| [Phase 6 — MFA / TOTP](phase6-mfa.md) | AES-256-GCM encryption, TOTP lifecycle, QR code |
| [Phase 7 — Containerisation](phase7-containerisation.md) | Dockerfile, docker-compose, volume strategy |

## Key invariants (enforced across the whole codebase)

1. **No SQL outside `internal/repository/`.** The service and CLI layers never import `database/sql`.
2. **No plaintext secrets in the DB.** Passwords → bcrypt. Session tokens → SHA-256. TOTP secrets → AES-256-GCM.
3. **All DB operations take `context.Context`** as their first argument.
4. **Single SQLite connection.** `SetMaxOpenConns(1)` prevents write contention. `SetConnMaxLifetime(0)` keeps the connection alive.
5. **`ErrNotFound` is the sentinel** for missing rows. Callers use `errors.Is`, never string comparison.
6. **`ErrInvalidCredentials` is returned for both wrong password and unknown username.** No information leakage.
7. **Migrations are embedded.** The binary carries its own schema. No external migration files needed at runtime.
