package config

import (
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

	cfg.DBPath = getString("DB_PATH", "./data/authctl.db")

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

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}