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
	ErrMFANotEnabled      = errors.New("MFA is not enabled on this account")
	ErrMFAAlreadyEnabled  = errors.New("MFA is already enabled on this account")
	ErrTOTPNotConfigured  = errors.New("TOTP secret not yet configured — run 'mfa setup' first")
	ErrMFAUnavailable     = errors.New("MFA is unavailable — TOTP_ENCRYPTION_KEY not configured")
)

// LoginResult carries the new session and a snapshot of the user taken before
// last_login_at is updated. Callers can display the previous login time before
// the current login overwrites it in the DB.
type LoginResult struct {
	Session *models.Session
	User    *models.User // LastLoginAt = time of the login BEFORE this one
}

// MFASetupResult carries the TOTP provisioning URI and the raw secret so the
// caller can display a QR code or a manual entry code to the user.
type MFASetupResult struct {
	Secret      string // base32 TOTP secret (show to user for manual entry)
	ProviderURI string // otpauth:// URI for QR code generation
}

// AuthService is the single entry point for all authentication operations.
// It enforces business rules; repositories handle persistence.
type AuthService interface {
	Register(ctx context.Context, username, password string) (*models.User, error)
	Login(ctx context.Context, username, password string) (*LoginResult, error)
	Logout(ctx context.Context, token string) error
	ValidateSession(ctx context.Context, token string) (*models.User, error)

	// MFA lifecycle — all three require TOTP_ENCRYPTION_KEY to be set.
	// SetupMFA generates a TOTP secret and stores it (encrypted) without activating MFA.
	SetupMFA(ctx context.Context, userID string) (*MFASetupResult, error)
	// VerifyAndEnableMFA confirms the first TOTP code then activates MFA.
	VerifyAndEnableMFA(ctx context.Context, userID, code string) error
	// DisableMFA deactivates MFA after verifying the supplied TOTP code.
	DisableMFA(ctx context.Context, userID, code string) error
	// VerifyMFALogin validates a TOTP code during the login flow.
	VerifyMFALogin(ctx context.Context, userID, code string) error
}
