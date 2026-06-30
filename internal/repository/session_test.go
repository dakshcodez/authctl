package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/dakshcodez/authctl/internal/models"
	"github.com/dakshcodez/authctl/internal/repository"
)

func newTestSession(userID string) *models.Session {
	return &models.Session{
		ID:        "sess-1",
		UserID:    userID,
		Token:     "plaintext-random-token",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		ExpiresAt: time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second),
		IsActive:  true,
	}
}

func setupUserAndSessionRepos(t *testing.T) (repository.UserRepository, repository.SessionRepository) {
	t.Helper()
	db := newTestDB(t)
	return repository.NewUserRepository(db), repository.NewSessionRepository(db)
}

func TestSessionRepository_Create_and_GetByToken(t *testing.T) {
	userRepo, sessRepo := setupUserAndSessionRepos(t)
	ctx := context.Background()

	userRepo.Create(ctx, newTestUser())
	s := newTestSession("user-1")

	if err := sessRepo.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := sessRepo.GetByToken(ctx, s.Token)
	if err != nil {
		t.Fatalf("GetByToken: %v", err)
	}
	if got.ID != s.ID || got.UserID != s.UserID {
		t.Errorf("got %+v, want ID=%q UserID=%q", got, s.ID, s.UserID)
	}
	if !got.IsActive {
		t.Error("expected session to be active")
	}
}

func TestSessionRepository_TokenIsHashed(t *testing.T) {
	userRepo, sessRepo := setupUserAndSessionRepos(t)
	ctx := context.Background()

	userRepo.Create(ctx, newTestUser())
	sessRepo.Create(ctx, newTestSession("user-1"))

	// The token stored in DB must not equal the plaintext token.
	got, _ := sessRepo.GetByToken(ctx, "plaintext-random-token")
	if got.Token == "plaintext-random-token" {
		t.Error("token must be hashed in DB, not stored as plaintext")
	}
}

func TestSessionRepository_GetByToken_NotFound(t *testing.T) {
	_, sessRepo := setupUserAndSessionRepos(t)
	_, err := sessRepo.GetByToken(context.Background(), "nonexistent")
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSessionRepository_Invalidate(t *testing.T) {
	userRepo, sessRepo := setupUserAndSessionRepos(t)
	ctx := context.Background()

	userRepo.Create(ctx, newTestUser())
	s := newTestSession("user-1")
	sessRepo.Create(ctx, s)

	if err := sessRepo.Invalidate(ctx, s.ID); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}

	got, _ := sessRepo.GetByToken(ctx, s.Token)
	if got.IsActive {
		t.Error("expected session to be inactive after invalidation")
	}
}

func TestSessionRepository_InvalidateAllForUser(t *testing.T) {
	userRepo, sessRepo := setupUserAndSessionRepos(t)
	ctx := context.Background()

	userRepo.Create(ctx, newTestUser())

	s1 := newTestSession("user-1")
	s2 := &models.Session{
		ID: "sess-2", UserID: "user-1", Token: "other-token",
		CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(), IsActive: true,
	}
	sessRepo.Create(ctx, s1)
	sessRepo.Create(ctx, s2)

	if err := sessRepo.InvalidateAllForUser(ctx, "user-1"); err != nil {
		t.Fatalf("InvalidateAllForUser: %v", err)
	}

	got1, _ := sessRepo.GetByToken(ctx, s1.Token)
	got2, _ := sessRepo.GetByToken(ctx, s2.Token)
	if got1.IsActive || got2.IsActive {
		t.Error("expected all user sessions to be inactive")
	}
}

func TestSessionRepository_DeleteExpired(t *testing.T) {
	userRepo, sessRepo := setupUserAndSessionRepos(t)
	ctx := context.Background()

	userRepo.Create(ctx, newTestUser())

	expired := &models.Session{
		ID: "sess-expired", UserID: "user-1", Token: "expired-token",
		CreatedAt: time.Now().Add(-2 * time.Hour).UTC(),
		ExpiresAt: time.Now().Add(-1 * time.Hour).UTC(),
		IsActive:  true,
	}
	sessRepo.Create(ctx, expired)

	if err := sessRepo.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	_, err := sessRepo.GetByToken(ctx, expired.Token)
	if err != repository.ErrNotFound {
		t.Error("expected expired session to be deleted")
	}
}

func TestSession_IsValid(t *testing.T) {
	s := &models.Session{
		IsActive:  true,
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if !s.IsValid() {
		t.Error("expected valid session")
	}

	s.IsActive = false
	if s.IsValid() {
		t.Error("inactive session must be invalid")
	}

	s.IsActive = true
	s.ExpiresAt = time.Now().Add(-time.Minute)
	if s.IsValid() {
		t.Error("expired session must be invalid")
	}
}
