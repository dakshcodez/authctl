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

	return nil
}