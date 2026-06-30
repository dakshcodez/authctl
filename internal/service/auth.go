package service

import (
	"context"
	"errors"

	"github.com/dakshcodez/authctl/internal/models"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account temporarily locked")
	ErrUserExists         = errors.New("username already taken")
	ErrSessionNotFound    = errors.New("session not found or expired")
	ErrMFARequired        = errors.New("MFA code required")
	ErrInvalidMFACode     = errors.New("invalid MFA code")
)

// AuthService is the single entry point for all authentication operations.
// It enforces business rules; repositories handle persistence.
type AuthService interface {
	Register(ctx context.Context, username, password string) (*models.User, error)
	Login(ctx context.Context, username, password string) (*models.Session, error)
	Logout(ctx context.Context, token string) error
	ValidateSession(ctx context.Context, token string) (*models.User, error)
}
