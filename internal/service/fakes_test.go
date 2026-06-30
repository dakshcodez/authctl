package service_test

import (
	"context"
	"time"

	"github.com/dakshcodez/authctl/internal/models"
	"github.com/dakshcodez/authctl/internal/repository"
)

// fakeUserRepo is an in-memory UserRepository for testing.
type fakeUserRepo struct {
	byID       map[string]*models.User
	byUsername map[string]*models.User
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{
		byID:       make(map[string]*models.User),
		byUsername: make(map[string]*models.User),
	}
}

func (r *fakeUserRepo) Create(_ context.Context, u *models.User) error {
	if _, exists := r.byUsername[u.Username]; exists {
		return repository.ErrNotFound // reuse sentinel to signal conflict
	}
	cp := *u
	r.byID[u.ID] = &cp
	r.byUsername[u.Username] = &cp
	return nil
}

func (r *fakeUserRepo) GetByUsername(_ context.Context, username string) (*models.User, error) {
	u, ok := r.byUsername[username]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (r *fakeUserRepo) GetByID(_ context.Context, id string) (*models.User, error) {
	u, ok := r.byID[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (r *fakeUserRepo) IncrementFailedAttempts(_ context.Context, id string, at time.Time) error {
	u, ok := r.byID[id]
	if !ok {
		return repository.ErrNotFound
	}
	u.FailedAttempts++
	u.LastFailedAt = &at
	r.byUsername[u.Username] = u
	return nil
}

func (r *fakeUserRepo) LockUntil(_ context.Context, id string, until time.Time) error {
	u, ok := r.byID[id]
	if !ok {
		return repository.ErrNotFound
	}
	u.LockedUntil = &until
	r.byUsername[u.Username] = u
	return nil
}

func (r *fakeUserRepo) ResetFailedAttempts(_ context.Context, id string) error {
	u, ok := r.byID[id]
	if !ok {
		return repository.ErrNotFound
	}
	u.FailedAttempts = 0
	u.LastFailedAt = nil
	u.LockedUntil = nil
	r.byUsername[u.Username] = u
	return nil
}

func (r *fakeUserRepo) UpdateLastLogin(_ context.Context, id string, at time.Time) error {
	u, ok := r.byID[id]
	if !ok {
		return repository.ErrNotFound
	}
	u.LastLoginAt = &at
	r.byUsername[u.Username] = u
	return nil
}

func (r *fakeUserRepo) EnableMFA(_ context.Context, id string, secret string) error {
	u, ok := r.byID[id]
	if !ok {
		return repository.ErrNotFound
	}
	u.MFAEnabled = true
	u.EncryptedTOTPSecret = &secret
	r.byUsername[u.Username] = u
	return nil
}

// fakeSessionRepo is an in-memory SessionRepository for testing.
type fakeSessionRepo struct {
	byID    map[string]*models.Session
	byToken map[string]*models.Session
}

func newFakeSessionRepo() *fakeSessionRepo {
	return &fakeSessionRepo{
		byID:    make(map[string]*models.Session),
		byToken: make(map[string]*models.Session),
	}
}

func (r *fakeSessionRepo) Create(_ context.Context, s *models.Session) error {
	cp := *s
	r.byID[s.ID] = &cp
	r.byToken[s.Token] = &cp
	return nil
}

func (r *fakeSessionRepo) GetByToken(_ context.Context, token string) (*models.Session, error) {
	s, ok := r.byToken[token]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := *s
	return &cp, nil
}

func (r *fakeSessionRepo) Invalidate(_ context.Context, id string) error {
	s, ok := r.byID[id]
	if !ok {
		return repository.ErrNotFound
	}
	s.IsActive = false
	// update the token-keyed copy too
	for _, ts := range r.byToken {
		if ts.ID == id {
			ts.IsActive = false
		}
	}
	return nil
}

func (r *fakeSessionRepo) InvalidateAllForUser(_ context.Context, userID string) error {
	for _, s := range r.byID {
		if s.UserID == userID {
			s.IsActive = false
		}
	}
	return nil
}

func (r *fakeSessionRepo) DeleteExpired(_ context.Context) error {
	now := time.Now()
	for id, s := range r.byID {
		if s.ExpiresAt.Before(now) {
			delete(r.byID, id)
			delete(r.byToken, s.Token)
		}
	}
	return nil
}
