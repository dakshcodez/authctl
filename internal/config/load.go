package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/joho/godotenv"
)

func Load() (*Config, error) {
	// Ignore error if .env doesn't exist
	_ = godotenv.Load()

	cfg := &Config{}

	var err error

	cfg.AppEnv = getString("APP_ENV", "development")

	cfg.LogLevel = getString("LOG_LEVEL", "info")

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}
	cfg.DBPath = getString("DB_PATH", filepath.Join(homeDir, ".authctl", "authctl.db"))

	cfg.SessionTimeout, err = getDuration(
		"SESSION_TIMEOUT",
		30*time.Minute,
	)
	if err != nil {
		return nil, err
	}

	cfg.MaxLoginAttempts, err = getInt(
		"MAX_LOGIN_ATTEMPTS",
		5,
	)
	if err != nil {
		return nil, err
	}

	cfg.LockoutDuration, err = getDuration(
		"LOCKOUT_DURATION",
		15*time.Minute,
	)
	if err != nil {
		return nil, err
	}

	cfg.BcryptCost, err = getInt(
		"BCRYPT_COST",
		12,
	)
	if err != nil {
		return nil, err
	}

	if raw := getString("TOTP_ENCRYPTION_KEY", ""); raw != "" {
		key, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("TOTP_ENCRYPTION_KEY must be a valid hex string: %w", err)
		}
		cfg.TOTPEncryptionKey = key
	}

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}