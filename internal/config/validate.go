package config

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

func validate(cfg *Config) error {

	if cfg.SessionTimeout <= 0 {
		return errors.New("session timeout must be positive")
	}

	if cfg.MaxLoginAttempts <= 0 {
		return errors.New("max login attempts must be positive")
	}

	if cfg.LockoutDuration <= 0 {
		return errors.New("lockout duration must be positive")
	}

	if cfg.BcryptCost < bcrypt.MinCost ||
		cfg.BcryptCost > bcrypt.MaxCost {
		return errors.New("invalid bcrypt cost")
	}

	if len(cfg.TOTPEncryptionKey) != 0 && len(cfg.TOTPEncryptionKey) != 32 {
		return errors.New("TOTP_ENCRYPTION_KEY must be exactly 32 bytes (64 hex characters)")
	}

	return nil
}