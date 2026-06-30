package session

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

var ErrNoSession = errors.New("no active session")

// StoredSession is the on-disk representation of a CLI session.
type StoredSession struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *StoredSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// Store persists and retrieves the current CLI session token on disk.
type Store interface {
	Save(s *StoredSession) error
	Load() (*StoredSession, error)
	Clear() error
}

type fileStore struct {
	path string
}

// NewFileStore returns a Store that persists sessions at the given path.
// Use DefaultPath() to get the standard ~/.authctl/session location.
func NewFileStore(path string) Store {
	return &fileStore{path: path}
}

// DefaultPath returns ~/.authctl/session.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".authctl", "session"), nil
}

func (f *fileStore) Save(s *StoredSession) error {
	if err := os.MkdirAll(filepath.Dir(f.path), 0700); err != nil {
		return err
	}

	data, err := json.Marshal(s)
	if err != nil {
		return err
	}

	// WriteFile with 0600: only the owner can read the session token.
	return os.WriteFile(f.path, data, 0600)
}

func (f *fileStore) Load() (*StoredSession, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}

	var s StoredSession
	if err := json.Unmarshal(data, &s); err != nil {
		// Corrupted file — treat as no session rather than a fatal error.
		return nil, ErrNoSession
	}

	if s.IsExpired() {
		_ = f.Clear()
		return nil, ErrNoSession
	}

	return &s, nil
}

func (f *fileStore) Clear() error {
	err := os.Remove(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
