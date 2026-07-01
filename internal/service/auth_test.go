package service_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/dakshcodez/authctl/internal/config"
	"github.com/dakshcodez/authctl/internal/logger"
	"github.com/dakshcodez/authctl/internal/service"
)

func newTestService(t *testing.T) (service.AuthService, *fakeUserRepo, *fakeSessionRepo) {
	t.Helper()
	cfg := &config.Config{
		BcryptCost:       4, // minimum cost for fast tests
		SessionTimeout:   30 * time.Minute,
		MaxLoginAttempts: 3,
		LockoutDuration:  15 * time.Minute,
		AppEnv:           "test",
		LogLevel:         "error",
	}
	log := logger.New(cfg, io.Discard)
	users := newFakeUserRepo()
	sessions := newFakeSessionRepo()
	svc := service.NewAuthService(users, sessions, cfg, log)
	return svc, users, sessions
}

func TestAuthService_Register(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "alice", "hunter2")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.ID == "" || user.Username != "alice" {
		t.Errorf("unexpected user: %+v", user)
	}
	if user.PasswordHash == "hunter2" {
		t.Error("password must be hashed, not stored in plaintext")
	}
}

func TestAuthService_Register_DuplicateUsername(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "pass1")
	_, err := svc.Register(ctx, "alice", "pass2")
	if err != service.ErrUserExists {
		t.Errorf("expected ErrUserExists, got %v", err)
	}
}

func TestAuthService_Login(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "correct-password")

	result, err := svc.Login(ctx, "alice", "correct-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result == nil || result.Session.Token == "" {
		t.Error("expected non-empty session token")
	}
	if !result.Session.IsActive {
		t.Error("session must be active after login")
	}
}

func TestAuthService_Login_WrongPassword(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "correct")

	_, err := svc.Login(ctx, "alice", "wrong")
	if err != service.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthService_Login_UnknownUser(t *testing.T) {
	svc, _, _ := newTestService(t)

	_, err := svc.Login(context.Background(), "nobody", "pass")
	if err != service.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials (no user enumeration), got %v", err)
	}
}

func TestAuthService_Login_AccountLockout(t *testing.T) {
	svc, users, _ := newTestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "correct")

	// Exhaust all attempts.
	for range 3 {
		svc.Login(ctx, "alice", "wrong")
	}

	// Even the correct password should now be rejected.
	_, err := svc.Login(ctx, "alice", "correct")
	if err != service.ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}

	// Confirm lock is persisted.
	u, _ := users.GetByUsername(ctx, "alice")
	if !u.IsLocked() {
		t.Error("expected user to have LockedUntil set")
	}
}

func TestAuthService_Login_ResetsFailedAttemptsOnSuccess(t *testing.T) {
	svc, users, _ := newTestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "correct")
	svc.Login(ctx, "alice", "wrong")
	svc.Login(ctx, "alice", "wrong")

	// Successful login should reset counter.
	svc.Login(ctx, "alice", "correct")

	u, _ := users.GetByUsername(ctx, "alice")
	if u.FailedAttempts != 0 {
		t.Errorf("expected FailedAttempts=0 after successful login, got %d", u.FailedAttempts)
	}
}

func TestAuthService_ValidateSession(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "pass")
	result, _ := svc.Login(ctx, "alice", "pass")

	user, err := svc.ValidateSession(ctx, result.Session.Token)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if user.Username != "alice" {
		t.Errorf("expected alice, got %s", user.Username)
	}
}

func TestAuthService_ValidateSession_InvalidToken(t *testing.T) {
	svc, _, _ := newTestService(t)

	_, err := svc.ValidateSession(context.Background(), "not-a-real-token")
	if err != service.ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestAuthService_Logout(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "pass")
	result, _ := svc.Login(ctx, "alice", "pass")

	if err := svc.Logout(ctx, result.Session.Token); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	_, err := svc.ValidateSession(ctx, result.Session.Token)
	if err != service.ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound after logout, got %v", err)
	}
}

func TestAuthService_Logout_IdempotentOnUnknownToken(t *testing.T) {
	svc, _, _ := newTestService(t)

	err := svc.Logout(context.Background(), "nonexistent-token")
	if err != nil {
		t.Errorf("Logout with unknown token should be silent, got %v", err)
	}
}

func TestAuthService_SessionToken_IsUnique(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "pass")

	r1, _ := svc.Login(ctx, "alice", "pass")
	svc.Logout(ctx, r1.Session.Token)
	r2, _ := svc.Login(ctx, "alice", "pass")

	if r1.Session.Token == r2.Session.Token {
		t.Error("session tokens must not repeat")
	}
}
