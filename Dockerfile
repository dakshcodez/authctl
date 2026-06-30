# syntax=docker/dockerfile:1

# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

# CGO is required by mattn/go-sqlite3.
RUN apk add --no-cache gcc musl-dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -trimpath -ldflags="-s -w" -o /authctl ./cmd/authctl

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.20

# ca-certificates for future TLS; tzdata for correct timestamps.
RUN apk add --no-cache ca-certificates tzdata

# Run as a non-root user.
RUN adduser -D -u 1000 authctl
USER authctl

WORKDIR /home/authctl

# Pre-create the data directory as the authctl user so Docker seeds the named
# volume with uid 1000 ownership instead of root when it is first initialised.
RUN mkdir -p /home/authctl/.authctl

VOLUME ["/home/authctl/.authctl"]

COPY --from=builder /authctl /usr/local/bin/authctl

ENTRYPOINT ["authctl"]
