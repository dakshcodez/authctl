package service_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/dakshcodez/authctl/internal/config"
	"github.com/dakshcodez/authctl/internal/logger"
	"github.com/dakshcodez/authctl/internal/service"
)

func newMFATestService(t *testing.T) (service.AuthService, *fakeUserRepo, *fakeSessionRepo) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1) // deterministic but non-zero
	}
	cfg := &config.Config{
		BcryptCost:        4,
		SessionTimeout:    30 * time.Minute,
		MaxLoginAttempts:  3,
		LockoutDuration:   15 * time.Minute,
		AppEnv:            "test",
		LogLevel:          "error",
		TOTPEncryptionKey: key,
	}
	log := logger.New(cfg, io.Discard)
	users := newFakeUserRepo()
	sessions := newFakeSessionRepo()
	svc := service.NewAuthService(users, sessions, cfg, log)
	return svc, users, sessions
}

func TestMFA_SetupThenVerifyAndEnable(t *testing.T) {
	svc, _, _ := newMFATestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "pass")
	result, _ := svc.Login(ctx, "alice", "pass")
	userID := result.User.ID

	setup, err := svc.SetupMFA(ctx, userID)
	if err != nil {
		t.Fatalf("SetupMFA: %v", err)
	}
	if setup.Secret == "" || setup.ProviderURI == "" {
		t.Fatal("expected non-empty secret and URI")
	}

	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	if err := svc.VerifyAndEnableMFA(ctx, userID, code); err != nil {
		t.Fatalf("VerifyAndEnableMFA: %v", err)
	}
}

func TestMFA_LoginRequiresMFAAfterEnable(t *testing.T) {
	svc, _, _ := newMFATestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "pass")
	result, _ := svc.Login(ctx, "alice", "pass")
	userID := result.User.ID

	setup, _ := svc.SetupMFA(ctx, userID)
	code, _ := totp.GenerateCode(setup.Secret, time.Now())
	svc.VerifyAndEnableMFA(ctx, userID, code)

	_, err := svc.Login(ctx, "alice", "pass")
	if err != service.ErrMFARequired {
		t.Errorf("expected ErrMFARequired, got %v", err)
	}
}

func TestMFA_VerifyMFALogin_ValidCode(t *testing.T) {
	svc, _, _ := newMFATestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "pass")
	result, _ := svc.Login(ctx, "alice", "pass")
	userID := result.User.ID

	setup, _ := svc.SetupMFA(ctx, userID)
	code, _ := totp.GenerateCode(setup.Secret, time.Now())
	svc.VerifyAndEnableMFA(ctx, userID, code)

	loginCode, _ := totp.GenerateCode(setup.Secret, time.Now())
	if err := svc.VerifyMFALogin(ctx, userID, loginCode); err != nil {
		t.Fatalf("VerifyMFALogin: %v", err)
	}
}

func TestMFA_VerifyMFALogin_InvalidCode(t *testing.T) {
	svc, _, _ := newMFATestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "pass")
	result, _ := svc.Login(ctx, "alice", "pass")
	userID := result.User.ID

	setup, _ := svc.SetupMFA(ctx, userID)
	code, _ := totp.GenerateCode(setup.Secret, time.Now())
	svc.VerifyAndEnableMFA(ctx, userID, code)

	err := svc.VerifyMFALogin(ctx, userID, "000000")
	if err != service.ErrInvalidMFACode {
		t.Errorf("expected ErrInvalidMFACode, got %v", err)
	}
}

func TestMFA_DisableMFA(t *testing.T) {
	svc, _, _ := newMFATestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "pass")
	result, _ := svc.Login(ctx, "alice", "pass")
	userID := result.User.ID

	setup, _ := svc.SetupMFA(ctx, userID)
	code, _ := totp.GenerateCode(setup.Secret, time.Now())
	svc.VerifyAndEnableMFA(ctx, userID, code)

	disableCode, _ := totp.GenerateCode(setup.Secret, time.Now())
	if err := svc.DisableMFA(ctx, userID, disableCode); err != nil {
		t.Fatalf("DisableMFA: %v", err)
	}

	// After disable, login should work without MFA.
	_, err := svc.Login(ctx, "alice", "pass")
	if err != nil {
		t.Errorf("expected login without MFA after disable, got %v", err)
	}
}

func TestMFA_DisableMFA_WrongCode(t *testing.T) {
	svc, _, _ := newMFATestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "pass")
	result, _ := svc.Login(ctx, "alice", "pass")
	userID := result.User.ID

	setup, _ := svc.SetupMFA(ctx, userID)
	code, _ := totp.GenerateCode(setup.Secret, time.Now())
	svc.VerifyAndEnableMFA(ctx, userID, code)

	err := svc.DisableMFA(ctx, userID, "000000")
	if err != service.ErrInvalidMFACode {
		t.Errorf("expected ErrInvalidMFACode, got %v", err)
	}
}

func TestMFA_SetupMFA_AlreadyEnabled(t *testing.T) {
	svc, _, _ := newMFATestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "pass")
	result, _ := svc.Login(ctx, "alice", "pass")
	userID := result.User.ID

	setup, _ := svc.SetupMFA(ctx, userID)
	code, _ := totp.GenerateCode(setup.Secret, time.Now())
	svc.VerifyAndEnableMFA(ctx, userID, code)

	_, err := svc.SetupMFA(ctx, userID)
	if err != service.ErrMFAAlreadyEnabled {
		t.Errorf("expected ErrMFAAlreadyEnabled, got %v", err)
	}
}

func TestMFA_Unavailable_WhenNoKey(t *testing.T) {
	// Service without encryption key.
	cfg := &config.Config{
		BcryptCost:       4,
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
	ctx := context.Background()

	svc.Register(ctx, "alice", "pass")
	result, _ := svc.Login(ctx, "alice", "pass")

	_, err := svc.SetupMFA(ctx, result.User.ID)
	if err != service.ErrMFAUnavailable {
		t.Errorf("expected ErrMFAUnavailable, got %v", err)
	}
}

func TestMFA_VerifyAndEnable_WithoutSetup(t *testing.T) {
	svc, _, _ := newMFATestService(t)
	ctx := context.Background()

	svc.Register(ctx, "alice", "pass")
	result, _ := svc.Login(ctx, "alice", "pass")

	err := svc.VerifyAndEnableMFA(ctx, result.User.ID, "123456")
	if err != service.ErrTOTPNotConfigured {
		t.Errorf("expected ErrTOTPNotConfigured, got %v", err)
	}
}
