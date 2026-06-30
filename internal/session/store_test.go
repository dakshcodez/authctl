package session_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dakshcodez/authctl/internal/session"
)

func newTestStore(t *testing.T) session.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session")
	return session.NewFileStore(path)
}

func TestStore_SaveAndLoad(t *testing.T) {
	store := newTestStore(t)

	s := &session.StoredSession{
		Token:     "test-token-abc",
		Username:  "alice",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	if err := store.Save(s); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got.Token != s.Token || got.Username != s.Username {
		t.Errorf("loaded %+v, want %+v", got, s)
	}
}

func TestStore_Load_NoSession(t *testing.T) {
	store := newTestStore(t)

	_, err := store.Load()
	if err != session.ErrNoSession {
		t.Errorf("expected ErrNoSession, got %v", err)
	}
}

func TestStore_Load_ExpiredSession(t *testing.T) {
	store := newTestStore(t)

	expired := &session.StoredSession{
		Token:     "old-token",
		Username:  "alice",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	store.Save(expired)

	_, err := store.Load()
	if err != session.ErrNoSession {
		t.Errorf("expected ErrNoSession for expired session, got %v", err)
	}
}

func TestStore_Clear(t *testing.T) {
	store := newTestStore(t)

	store.Save(&session.StoredSession{
		Token:     "tok",
		Username:  "alice",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	if err := store.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	_, err := store.Load()
	if err != session.ErrNoSession {
		t.Errorf("expected ErrNoSession after clear, got %v", err)
	}
}

func TestStore_Clear_Idempotent(t *testing.T) {
	store := newTestStore(t)

	if err := store.Clear(); err != nil {
		t.Errorf("Clear on empty store should be a no-op, got %v", err)
	}
}

func TestStore_FilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session")
	store := session.NewFileStore(path)

	store.Save(&session.StoredSession{
		Token:     "tok",
		Username:  "alice",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("session file must have 0600 permissions, got %o", mode)
	}
}
