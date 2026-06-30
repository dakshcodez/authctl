package models

import "time"

type User struct {
	ID                  string
	Username            string
	PasswordHash        string
	MFAEnabled          bool
	EncryptedTOTPSecret *string
	FailedAttempts      int
	LastFailedAt        *time.Time
	LockedUntil         *time.Time
	RegisteredAt        time.Time
	LastLoginAt         *time.Time
}

func (u *User) IsLocked() bool {
	return u.LockedUntil != nil && u.LockedUntil.After(time.Now())
}
