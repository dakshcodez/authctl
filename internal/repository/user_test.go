package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/dakshcodez/authctl/internal/models"
	"github.com/dakshcodez/authctl/internal/repository"
)

func newTestUser() *models.User {
	return &models.User{
		ID:           "user-1",
		Username:     "alice",
		PasswordHash: "$2a$12$fakehash",
		RegisteredAt: time.Now().UTC().Truncate(time.Second),
	}
}

func TestUserRepository_Create_and_GetByUsername(t *testing.T) {
	repo := repository.NewUserRepository(newTestDB(t))
	ctx := context.Background()

	u := newTestUser()
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByUsername(ctx, u.Username)
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if got.ID != u.ID || got.Username != u.Username {
		t.Errorf("got %+v, want %+v", got, u)
	}
	if got.MFAEnabled {
		t.Error("expected MFAEnabled=false")
	}
}

func TestUserRepository_GetByUsername_NotFound(t *testing.T) {
	repo := repository.NewUserRepository(newTestDB(t))
	_, err := repo.GetByUsername(context.Background(), "nobody")
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUserRepository_GetByID(t *testing.T) {
	repo := repository.NewUserRepository(newTestDB(t))
	ctx := context.Background()

	u := newTestUser()
	repo.Create(ctx, u)

	got, err := repo.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("got ID %q, want %q", got.ID, u.ID)
	}
}

func TestUserRepository_IncrementFailedAttempts(t *testing.T) {
	repo := repository.NewUserRepository(newTestDB(t))
	ctx := context.Background()

	repo.Create(ctx, newTestUser())

	now := time.Now().UTC()
	if err := repo.IncrementFailedAttempts(ctx, "user-1", now); err != nil {
		t.Fatalf("IncrementFailedAttempts: %v", err)
	}

	u, _ := repo.GetByID(ctx, "user-1")
	if u.FailedAttempts != 1 {
		t.Errorf("expected FailedAttempts=1, got %d", u.FailedAttempts)
	}
	if u.LastFailedAt == nil {
		t.Error("expected LastFailedAt to be set")
	}
}

func TestUserRepository_LockUntil_and_IsLocked(t *testing.T) {
	repo := repository.NewUserRepository(newTestDB(t))
	ctx := context.Background()

	repo.Create(ctx, newTestUser())

	until := time.Now().Add(15 * time.Minute).UTC()
	if err := repo.LockUntil(ctx, "user-1", until); err != nil {
		t.Fatalf("LockUntil: %v", err)
	}

	u, _ := repo.GetByID(ctx, "user-1")
	if !u.IsLocked() {
		t.Error("expected user to be locked")
	}
}

func TestUserRepository_ResetFailedAttempts(t *testing.T) {
	repo := repository.NewUserRepository(newTestDB(t))
	ctx := context.Background()

	repo.Create(ctx, newTestUser())
	repo.IncrementFailedAttempts(ctx, "user-1", time.Now())
	repo.LockUntil(ctx, "user-1", time.Now().Add(time.Hour))

	if err := repo.ResetFailedAttempts(ctx, "user-1"); err != nil {
		t.Fatalf("ResetFailedAttempts: %v", err)
	}

	u, _ := repo.GetByID(ctx, "user-1")
	if u.FailedAttempts != 0 || u.LockedUntil != nil || u.LastFailedAt != nil {
		t.Errorf("expected clean state, got %+v", u)
	}
}

func TestUserRepository_EnableMFA(t *testing.T) {
	repo := repository.NewUserRepository(newTestDB(t))
	ctx := context.Background()

	repo.Create(ctx, newTestUser())
	if err := repo.EnableMFA(ctx, "user-1", "encrypted-secret"); err != nil {
		t.Fatalf("EnableMFA: %v", err)
	}

	u, _ := repo.GetByID(ctx, "user-1")
	if !u.MFAEnabled {
		t.Error("expected MFAEnabled=true")
	}
	if u.EncryptedTOTPSecret == nil || *u.EncryptedTOTPSecret != "encrypted-secret" {
		t.Errorf("unexpected EncryptedTOTPSecret: %v", u.EncryptedTOTPSecret)
	}
}

func TestUserRepository_DuplicateUsername(t *testing.T) {
	repo := repository.NewUserRepository(newTestDB(t))
	ctx := context.Background()

	repo.Create(ctx, newTestUser())

	dup := newTestUser()
	dup.ID = "user-2"
	err := repo.Create(ctx, dup)
	if err == nil {
		t.Error("expected error on duplicate username")
	}
}
