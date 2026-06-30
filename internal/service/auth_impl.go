package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/dakshcodez/authctl/internal/config"
	"github.com/dakshcodez/authctl/internal/logger"
	"github.com/dakshcodez/authctl/internal/models"
	"github.com/dakshcodez/authctl/internal/repository"
)

type authService struct {
	users    repository.UserRepository
	sessions repository.SessionRepository
	cfg      *config.Config
	log      *logger.Logger
}

func NewAuthService(
	users repository.UserRepository,
	sessions repository.SessionRepository,
	cfg *config.Config,
	log *logger.Logger,
) AuthService {
	return &authService{
		users:    users,
		sessions: sessions,
		cfg:      cfg,
		log:      log,
	}
}

func (s *authService) Register(ctx context.Context, username, password string) (*models.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := &models.User{
		ID:           uuid.NewString(),
		Username:     username,
		PasswordHash: string(hash),
		RegisteredAt: time.Now().UTC(),
	}

	if err := s.users.Create(ctx, user); err != nil {
		s.log.Audit("register failed: username taken", "username", username)
		return nil, ErrUserExists
	}

	s.log.Audit("user registered", "user_id", user.ID)
	return user, nil
}

func (s *authService) Login(ctx context.Context, username, password string) (*LoginResult, error) {
	user, err := s.users.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// Perform dummy bcrypt to prevent timing-based username enumeration.
			bcrypt.CompareHashAndPassword([]byte("$2a$12$dummyhashfortimingnoop00000000000000000000000000000000"), []byte(password)) //nolint:errcheck
			s.log.Security("login failed: unknown username", "username", username)
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("lookup user: %w", err)
	}

	if user.IsLocked() {
		s.log.Security("login blocked: account locked", "user_id", user.ID)
		return nil, ErrAccountLocked
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		s.handleFailedAttempt(ctx, user)
		s.log.Security("login failed: wrong password", "user_id", user.ID)
		return nil, ErrInvalidCredentials
	}

	if user.MFAEnabled {
		return nil, ErrMFARequired
	}

	if err := s.users.ResetFailedAttempts(ctx, user.ID); err != nil {
		return nil, fmt.Errorf("reset failed attempts: %w", err)
	}

	// Capture the user snapshot (with old LastLoginAt) before overwriting it.
	userSnapshot := *user

	session, err := s.createSession(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if err := s.users.UpdateLastLogin(ctx, user.ID, now); err != nil {
		return nil, fmt.Errorf("update last login: %w", err)
	}

	s.log.Audit("user logged in", "user_id", user.ID, "session_id", session.ID)
	return &LoginResult{Session: session, User: &userSnapshot}, nil
}

func (s *authService) Logout(ctx context.Context, token string) error {
	session, err := s.sessions.GetByToken(ctx, token)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("lookup session: %w", err)
	}

	if err := s.sessions.Invalidate(ctx, session.ID); err != nil {
		return fmt.Errorf("invalidate session: %w", err)
	}

	s.log.Audit("user logged out", "session_id", session.ID)
	return nil
}

func (s *authService) ValidateSession(ctx context.Context, token string) (*models.User, error) {
	session, err := s.sessions.GetByToken(ctx, token)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("lookup session: %w", err)
	}

	if !session.IsValid() {
		s.log.Security("invalid session presented", "session_id", session.ID)
		return nil, ErrSessionNotFound
	}

	user, err := s.users.GetByID(ctx, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("lookup user: %w", err)
	}

	return user, nil
}

func (s *authService) handleFailedAttempt(ctx context.Context, user *models.User) {
	now := time.Now().UTC()
	if err := s.users.IncrementFailedAttempts(ctx, user.ID, now); err != nil {
		s.log.Error("increment failed attempts", "error", err)
		return
	}

	if user.FailedAttempts+1 >= s.cfg.MaxLoginAttempts {
		until := now.Add(s.cfg.LockoutDuration)
		if err := s.users.LockUntil(ctx, user.ID, until); err != nil {
			s.log.Error("lock account", "error", err)
			return
		}
		s.log.Security("account locked", "user_id", user.ID, "until", until)
	}
}

func (s *authService) createSession(ctx context.Context, userID string) (*models.Session, error) {
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("generate session token: %w", err)
	}

	now := time.Now().UTC()
	session := &models.Session{
		ID:        uuid.NewString(),
		UserID:    userID,
		Token:     token,
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.SessionTimeout),
		IsActive:  true,
	}

	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return session, nil
}

func (s *authService) SetupMFA(ctx context.Context, userID string) (*MFASetupResult, error) {
	if len(s.cfg.TOTPEncryptionKey) == 0 {
		return nil, ErrMFAUnavailable
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("lookup user: %w", err)
	}
	if user.MFAEnabled {
		return nil, ErrMFAAlreadyEnabled
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "authctl",
		AccountName: user.Username,
	})
	if err != nil {
		return nil, fmt.Errorf("generate TOTP key: %w", err)
	}

	encrypted, err := encryptTOTPSecret(s.cfg.TOTPEncryptionKey, key.Secret())
	if err != nil {
		return nil, fmt.Errorf("encrypt TOTP secret: %w", err)
	}

	if err := s.users.StoreTOTPSecret(ctx, userID, encrypted); err != nil {
		return nil, fmt.Errorf("store TOTP secret: %w", err)
	}

	s.log.Audit("MFA setup initiated", "user_id", userID)
	return &MFASetupResult{
		Secret:      key.Secret(),
		ProviderURI: key.URL(),
	}, nil
}

func (s *authService) VerifyAndEnableMFA(ctx context.Context, userID, code string) error {
	if len(s.cfg.TOTPEncryptionKey) == 0 {
		return ErrMFAUnavailable
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}
	if user.MFAEnabled {
		return ErrMFAAlreadyEnabled
	}
	if user.EncryptedTOTPSecret == nil {
		return ErrTOTPNotConfigured
	}

	secret, err := decryptTOTPSecret(s.cfg.TOTPEncryptionKey, *user.EncryptedTOTPSecret)
	if err != nil {
		return fmt.Errorf("decrypt TOTP secret: %w", err)
	}

	if !totp.Validate(code, secret) {
		s.log.Security("MFA enable failed: invalid code", "user_id", userID)
		return ErrInvalidMFACode
	}

	if err := s.users.ActivateMFA(ctx, userID); err != nil {
		return fmt.Errorf("activate MFA: %w", err)
	}

	s.log.Audit("MFA enabled", "user_id", userID)
	return nil
}

func (s *authService) DisableMFA(ctx context.Context, userID, code string) error {
	if len(s.cfg.TOTPEncryptionKey) == 0 {
		return ErrMFAUnavailable
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}
	if !user.MFAEnabled {
		return ErrMFANotEnabled
	}
	if user.EncryptedTOTPSecret == nil {
		return ErrTOTPNotConfigured
	}

	secret, err := decryptTOTPSecret(s.cfg.TOTPEncryptionKey, *user.EncryptedTOTPSecret)
	if err != nil {
		return fmt.Errorf("decrypt TOTP secret: %w", err)
	}

	if !totp.Validate(code, secret) {
		s.log.Security("MFA disable failed: invalid code", "user_id", userID)
		return ErrInvalidMFACode
	}

	if err := s.users.DisableMFA(ctx, userID); err != nil {
		return fmt.Errorf("disable MFA: %w", err)
	}

	s.log.Audit("MFA disabled", "user_id", userID)
	return nil
}

func (s *authService) VerifyMFALogin(ctx context.Context, userID, code string) error {
	if len(s.cfg.TOTPEncryptionKey) == 0 {
		return ErrMFAUnavailable
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}
	if !user.MFAEnabled || user.EncryptedTOTPSecret == nil {
		return ErrMFANotEnabled
	}

	secret, err := decryptTOTPSecret(s.cfg.TOTPEncryptionKey, *user.EncryptedTOTPSecret)
	if err != nil {
		return fmt.Errorf("decrypt TOTP secret: %w", err)
	}

	if !totp.Validate(code, secret) {
		s.log.Security("MFA login failed: invalid code", "user_id", userID)
		return ErrInvalidMFACode
	}

	return nil
}

// generateToken returns 32 cryptographically random bytes as a hex string.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
