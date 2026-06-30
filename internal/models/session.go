package models

import "time"

type Session struct {
	ID        string
	UserID    string
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
	IsActive  bool
}

func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

func (s *Session) IsValid() bool {
	return s.IsActive && !s.IsExpired()
}
