package config

import "time"

type Config struct {
	AppEnv           string
	LogLevel         string
	DBPath           string
	SessionTimeout   time.Duration
	MaxLoginAttempts int
	LockoutDuration  time.Duration
	BcryptCost       int
	// TOTPEncryptionKey is the 32-byte AES-256 key used to encrypt TOTP secrets at rest.
	// Nil means MFA setup is unavailable. Set via TOTP_ENCRYPTION_KEY (64 hex chars).
	TOTPEncryptionKey []byte
}