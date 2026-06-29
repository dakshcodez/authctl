package config

import "time"

type Config struct {
	AppEnv string
	LogLevel string
	DBPath string
	SessionTimeout time.Duration
	MaxLoginAttempts int
	LockoutDuration time.Duration
	BcryptCost int
}