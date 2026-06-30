# Phase 7 — Containerisation

Packaging authctl as a Docker image with a minimal attack surface, a non-root runtime user, and persistent storage for the SQLite database.

## Files

```
Dockerfile
docker-compose.yml
.env.example
.env          (gitignored — user-created)
```

## Two-stage build

```dockerfile
FROM golang:1.25-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -trimpath -ldflags="-s -w" -o /authctl ./cmd/authctl

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -u 1000 authctl
USER authctl
WORKDIR /home/authctl
VOLUME ["/home/authctl/.authctl"]
COPY --from=builder /authctl /usr/local/bin/authctl
ENTRYPOINT ["authctl"]
```

### Builder stage

`golang:1.25-alpine` with `gcc` and `musl-dev` added. These are required by `mattn/go-sqlite3`, which is a CGO package — it compiles C code at build time.

`CGO_ENABLED=1` is set explicitly. Go defaults to `CGO_ENABLED=0` when cross-compiling; making it explicit prevents silent fallbacks.

`-trimpath` removes source file paths from the binary. Without it, the full build path appears in stack traces and `go:` directives, leaking information about the build environment.

`-ldflags="-s -w"` strips the symbol table (`-s`) and DWARF debug information (`-w`), reducing binary size by ~30% and removing information useful for reverse engineering.

### Runtime stage

`alpine:3.20` — minimal base image (~5MB). No Go toolchain, no build tools, no gcc. Only what is needed to run:
- `ca-certificates` — for TLS validation (used by future HTTPS features if added)
- `tzdata` — for correct timestamp display across timezones

`adduser -D -u 1000 authctl` creates a non-root user. The `-D` flag creates the user without a password. UID 1000 is explicit so the volume mount permissions are predictable across environments.

`USER authctl` switches the runtime user. The process cannot write to `/usr/local/bin/` or modify system files.

## Volume strategy

```dockerfile
VOLUME ["/home/authctl/.authctl"]
```

The SQLite database and CLI session file both live at `~/.authctl/` (or `/home/authctl/.authctl` inside the container). Declaring this path as a `VOLUME` signals that it needs persistent storage.

In `docker-compose.yml`, a named volume is mounted here:

```yaml
volumes:
  - authctl-data:/home/authctl/.authctl
```

Named volumes persist across `docker compose down` and container recreation. `docker compose down -v` removes the volume (wipes the database).

**Why a named volume rather than a bind mount?**
A named volume is managed by Docker and lives in Docker's storage driver. A bind mount would require a host path, which means the host directory must exist with the right ownership and permissions. Named volumes work correctly out of the box.

## docker-compose.yml

```yaml
services:
  authctl:
    build: .
    image: authctl:latest
    stdin_open: true
    tty: true
    volumes:
      - authctl-data:/home/authctl/.authctl
    env_file: .env
    environment:
      APP_ENV: production
      LOG_LEVEL: info
```

`stdin_open: true` and `tty: true` are both required for the readline shell. Without them:
- `stdin_open: false` — stdin is closed, readline returns EOF immediately
- `tty: false` — no terminal attributes, readline cannot set raw mode, passwords are echoed

`env_file: .env` loads the `.env` file from the project root. The `environment` block can override specific values. As shown, `APP_ENV=production` is always set in the compose file; `TOTP_ENCRYPTION_KEY` must come from `.env`.

## `.env` and secrets

`.env` is gitignored. `.env.example` is committed with all variables listed and empty values.

The `TOTP_ENCRYPTION_KEY` is the only true secret. It:
- Must be 64 hex characters (32 bytes)
- Must be generated fresh per deployment: `openssl rand -hex 32`
- Must not be committed to the repository
- Must be backed up separately from the database — if lost, all TOTP secrets are unrecoverable

All other config values in `.env` are operational settings (log level, timeouts) that are not sensitive.

## DB_PATH inside the container

`DB_PATH` defaults to `./data/authctl.db` (relative to the working directory) in `.env.example`. Inside the container, `WORKDIR` is `/home/authctl`, so this would place the database at `/home/authctl/data/authctl.db` — outside the volume.

The compose file does not set `DB_PATH` because the binary defaults to `~/.authctl/authctl.db` when `DB_PATH` is not set. In the container, `HOME=/home/authctl`, so the database lands inside the volume automatically.

If deploying with `docker run` (without compose), set `DB_PATH` explicitly:
```sh
docker run -it -e DB_PATH=/home/authctl/.authctl/authctl.db authctl:latest
```

## Running without Docker

For local development, the binary reads `.env` from the current directory via `godotenv.Load()`. No Docker required:

```sh
go build -o authctl ./cmd/authctl
./authctl
```

`CGO_ENABLED=1` must be set if the default is 0 in your Go installation. On Linux with gcc installed, it defaults to 1.
