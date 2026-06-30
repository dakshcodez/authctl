package cli_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dakshcodez/authctl/internal/cli"
	"github.com/dakshcodez/authctl/internal/config"
	"github.com/dakshcodez/authctl/internal/logger"
	"github.com/dakshcodez/authctl/internal/models"
	"github.com/dakshcodez/authctl/internal/service"
	"github.com/dakshcodez/authctl/internal/session"
)

// fakeAuth is a controllable AuthService for handler tests.
type fakeAuth struct {
	users    map[string]*models.User
	sessions map[string]*models.Session
	nextErr  error
}

func newFakeAuth() *fakeAuth {
	return &fakeAuth{
		users:    make(map[string]*models.User),
		sessions: make(map[string]*models.Session),
	}
}

func (f *fakeAuth) Register(_ context.Context, username, _ string) (*models.User, error) {
	if f.nextErr != nil {
		return nil, f.nextErr
	}
	if _, exists := f.users[username]; exists {
		return nil, service.ErrUserExists
	}
	u := &models.User{ID: "u-1", Username: username}
	f.users[username] = u
	return u, nil
}

func (f *fakeAuth) Login(_ context.Context, username, _ string) (*service.LoginResult, error) {
	if f.nextErr != nil {
		return nil, f.nextErr
	}
	u, exists := f.users[username]
	if !exists {
		return nil, service.ErrInvalidCredentials
	}
	s := &models.Session{
		ID:        "s-1",
		UserID:    u.ID,
		Token:     "fake-token",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * time.Minute),
		IsActive:  true,
	}
	f.sessions["fake-token"] = s
	return &service.LoginResult{Session: s, User: u}, nil
}

func (f *fakeAuth) Logout(_ context.Context, token string) error {
	if f.nextErr != nil {
		return f.nextErr
	}
	delete(f.sessions, token)
	return nil
}

func (f *fakeAuth) ValidateSession(_ context.Context, token string) (*models.User, error) {
	if f.nextErr != nil {
		return nil, f.nextErr
	}
	s, ok := f.sessions[token]
	if !ok || !s.IsValid() {
		return nil, service.ErrSessionNotFound
	}
	return &models.User{ID: "u-1", Username: "alice"}, nil
}

func (f *fakeAuth) LoginWithMFA(_ context.Context, _, _, _ string) (*service.LoginResult, error) {
	return nil, service.ErrMFAUnavailable
}

func (f *fakeAuth) SetupMFA(_ context.Context, _ string) (*service.MFASetupResult, error) {
	return nil, service.ErrMFAUnavailable
}

func (f *fakeAuth) VerifyAndEnableMFA(_ context.Context, _, _ string) error {
	return service.ErrMFAUnavailable
}

func (f *fakeAuth) DisableMFA(_ context.Context, _, _ string) error {
	return service.ErrMFAUnavailable
}

func (f *fakeAuth) VerifyMFALogin(_ context.Context, _, _ string) error {
	return service.ErrMFAUnavailable
}

// fakePrompter returns preset values for password and line prompts.
type fakePrompter struct {
	passwords []string
	lines     []string
	pwIdx     int
	lineIdx   int
	nextPwErr error // if set, next ReadPassword returns this error instead
}

func (p *fakePrompter) ReadPassword(_ string) (string, error) {
	if p.nextPwErr != nil {
		err := p.nextPwErr
		p.nextPwErr = nil
		return "", err
	}
	if p.pwIdx >= len(p.passwords) {
		return "", errors.New("no more passwords")
	}
	val := p.passwords[p.pwIdx]
	p.pwIdx++
	return val, nil
}

func (p *fakePrompter) ReadLine(_ string) (string, error) {
	if p.lineIdx >= len(p.lines) {
		return "", errors.New("no more lines")
	}
	val := p.lines[p.lineIdx]
	p.lineIdx++
	return val, nil
}

func (p *fakePrompter) SetPrompt(_ string) {} // no-op in tests

func newTestHandler(t *testing.T, auth service.AuthService) (*cli.Handler, *bytes.Buffer, *fakePrompter, session.Store) {
	t.Helper()
	out := &bytes.Buffer{}
	prompter := &fakePrompter{}
	store := session.NewFileStore(filepath.Join(t.TempDir(), "session"))
	cfg := &config.Config{AppEnv: "test", LogLevel: "error"}
	log := logger.New(cfg)
	_ = log // handler doesn't take logger; auth service does
	h := cli.NewHandler(auth, store, out, prompter)
	return h, out, prompter, store
}

func TestHandler_Register(t *testing.T) {
	auth := newFakeAuth()
	auth.users["alice"] = &models.User{} // pre-seed so login works later
	delete(auth.users, "alice")          // clean up

	h, out, prompter, _ := newTestHandler(t, auth)
	prompter.lines = []string{"alice"}
	prompter.passwords = []string{"password123", "password123"}

	h.Dispatch("register")

	if !strings.Contains(out.String(), "Registered successfully") {
		t.Errorf("unexpected output: %q", out.String())
	}
}

func TestHandler_Register_PasswordMismatch(t *testing.T) {
	h, out, prompter, _ := newTestHandler(t, newFakeAuth())
	prompter.lines = []string{"alice"}
	prompter.passwords = []string{"password123", "different456"}

	h.Dispatch("register")

	if !strings.Contains(out.String(), "passwords do not match") {
		t.Errorf("expected mismatch error, got: %q", out.String())
	}
}

func TestHandler_Register_ShortPassword(t *testing.T) {
	h, out, prompter, _ := newTestHandler(t, newFakeAuth())
	prompter.lines = []string{"alice"}
	prompter.passwords = []string{"short", "short"}

	h.Dispatch("register")

	if !strings.Contains(out.String(), "at least 8 characters") {
		t.Errorf("expected length error, got: %q", out.String())
	}
}

func TestHandler_Login(t *testing.T) {
	auth := newFakeAuth()
	auth.users["alice"] = &models.User{ID: "u-1", Username: "alice"}

	h, out, prompter, store := newTestHandler(t, auth)
	prompter.passwords = []string{"anypassword"}

	h.Dispatch("login alice")

	if !strings.Contains(out.String(), "Login Successful") || !strings.Contains(out.String(), "alice") {
		t.Errorf("unexpected output: %q", out.String())
	}

	stored, err := store.Load()
	if err != nil {
		t.Fatalf("session not saved: %v", err)
	}
	if stored.Username != "alice" {
		t.Errorf("stored username = %q, want alice", stored.Username)
	}
}

func TestHandler_Login_InvalidCredentials(t *testing.T) {
	h, out, prompter, _ := newTestHandler(t, newFakeAuth())
	prompter.passwords = []string{"wrongpass"}

	h.Dispatch("login nobody")

	if !strings.Contains(out.String(), "invalid username or password") {
		t.Errorf("expected credentials error, got: %q", out.String())
	}
}

func TestHandler_Logout(t *testing.T) {
	auth := newFakeAuth()
	auth.users["alice"] = &models.User{ID: "u-1", Username: "alice"}

	h, out, prompter, store := newTestHandler(t, auth)
	prompter.passwords = []string{"pass"}
	h.Dispatch("login alice")
	out.Reset()

	h.Dispatch("logout")

	if !strings.Contains(out.String(), "Logged out") {
		t.Errorf("unexpected output: %q", out.String())
	}
	if _, err := store.Load(); err != session.ErrNoSession {
		t.Error("expected session to be cleared after logout")
	}
}

func TestHandler_Login_AlreadyLoggedIn(t *testing.T) {
	auth := newFakeAuth()
	auth.users["alice"] = &models.User{ID: "u-1", Username: "alice"}

	h, out, prompter, _ := newTestHandler(t, auth)
	prompter.passwords = []string{"pass", "pass"}

	h.Dispatch("login alice")
	out.Reset()

	// Second login attempt must be rejected without creating a new session.
	h.Dispatch("login alice")

	if !strings.Contains(out.String(), "already logged in") {
		t.Errorf("expected already-logged-in warning, got: %q", out.String())
	}
}

func TestHandler_Logout_NotLoggedIn(t *testing.T) {
	h, out, _, _ := newTestHandler(t, newFakeAuth())

	h.Dispatch("logout")

	if !strings.Contains(out.String(), "Not logged in") {
		t.Errorf("unexpected output: %q", out.String())
	}
}

func TestHandler_Whoami_NotLoggedIn(t *testing.T) {
	h, out, _, _ := newTestHandler(t, newFakeAuth())

	h.Dispatch("whoami")

	if !strings.Contains(out.String(), "Not logged in") {
		t.Errorf("unexpected output: %q", out.String())
	}
}

func TestHandler_Whoami_LoggedIn(t *testing.T) {
	auth := newFakeAuth()
	auth.users["alice"] = &models.User{ID: "u-1", Username: "alice"}

	h, out, prompter, _ := newTestHandler(t, auth)
	prompter.passwords = []string{"pass"}
	h.Dispatch("login alice")
	out.Reset()

	h.Dispatch("whoami")

	if !strings.Contains(out.String(), "alice") {
		t.Errorf("expected username in output, got: %q", out.String())
	}
}

func TestHandler_UnknownCommand(t *testing.T) {
	h, out, _, _ := newTestHandler(t, newFakeAuth())

	h.Dispatch("foobar")

	if !strings.Contains(out.String(), "unknown command") {
		t.Errorf("expected unknown command message, got: %q", out.String())
	}
}

func TestHandler_Register_WhileLoggedIn(t *testing.T) {
	auth := newFakeAuth()
	auth.users["alice"] = &models.User{ID: "u-1", Username: "alice"}

	h, out, prompter, _ := newTestHandler(t, auth)
	prompter.passwords = []string{"pass"}
	h.Dispatch("login alice")
	out.Reset()

	prompter.lines = []string{"bob"}
	prompter.passwords = []string{"password123", "password123"}
	h.Dispatch("register")

	if !strings.Contains(out.String(), "logged in as alice") {
		t.Errorf("expected already-logged-in warning, got: %q", out.String())
	}
	if _, exists := auth.users["bob"]; exists {
		t.Error("register must not create a new user while another session is active")
	}
}

func TestHandler_Interrupt_Swallowed(t *testing.T) {
	h, out, prompter, _ := newTestHandler(t, newFakeAuth())
	prompter.lines = []string{"alice"}
	prompter.nextPwErr = cli.ErrInterrupted

	h.Dispatch("register")

	// Must not print "error: interrupted" — just a blank line.
	if strings.Contains(out.String(), "error") {
		t.Errorf("interrupt must be swallowed silently, got: %q", out.String())
	}
}

func TestHandler_Clear(t *testing.T) {
	h, out, _, _ := newTestHandler(t, newFakeAuth())

	h.Dispatch("clear")

	// Should contain the ANSI clear sequence, not an "unknown command" error.
	if strings.Contains(out.String(), "unknown command") {
		t.Errorf("clear must not produce unknown-command error")
	}
	if !strings.Contains(out.String(), "\033[H\033[2J") {
		t.Errorf("clear must write ANSI clear sequence, got: %q", out.String())
	}
}

func TestHandler_Help(t *testing.T) {
	h, out, _, _ := newTestHandler(t, newFakeAuth())

	h.Dispatch("help")

	for _, cmd := range []string{"register", "login", "logout", "whoami", "mfa", "clear"} {
		if !strings.Contains(out.String(), cmd) {
			t.Errorf("help output missing %q", cmd)
		}
	}
}

func TestHandler_MFA_NotLoggedIn(t *testing.T) {
	h, out, _, _ := newTestHandler(t, newFakeAuth())

	h.Dispatch("mfa setup")

	if !strings.Contains(out.String(), "Not logged in") {
		t.Errorf("expected not-logged-in warning, got: %q", out.String())
	}
}

func TestHandler_MFA_Unavailable(t *testing.T) {
	// fakeAuth returns ErrMFAUnavailable for all MFA methods.
	auth := newFakeAuth()
	auth.users["alice"] = &models.User{ID: "u-1", Username: "alice"}

	h, out, prompter, _ := newTestHandler(t, auth)
	prompter.passwords = []string{"pass"}
	h.Dispatch("login alice")
	out.Reset()

	h.Dispatch("mfa setup")

	if !strings.Contains(out.String(), "MFA is unavailable") {
		t.Errorf("expected unavailable message, got: %q", out.String())
	}
}

func TestHandler_MFA_NoSubcommand(t *testing.T) {
	h, out, _, _ := newTestHandler(t, newFakeAuth())

	h.Dispatch("mfa")

	if !strings.Contains(out.String(), "Usage") {
		t.Errorf("expected usage hint, got: %q", out.String())
	}
}

func TestHandler_MFA_Enable_MissingCode(t *testing.T) {
	auth := newFakeAuth()
	auth.users["alice"] = &models.User{ID: "u-1", Username: "alice"}

	h, out, prompter, _ := newTestHandler(t, auth)
	prompter.passwords = []string{"pass"}
	h.Dispatch("login alice")
	out.Reset()

	h.Dispatch("mfa enable")

	if !strings.Contains(out.String(), "Usage") {
		t.Errorf("expected usage hint, got: %q", out.String())
	}
}

func TestHandler_MFA_Disable_MissingCode(t *testing.T) {
	auth := newFakeAuth()
	auth.users["alice"] = &models.User{ID: "u-1", Username: "alice"}

	h, out, prompter, _ := newTestHandler(t, auth)
	prompter.passwords = []string{"pass"}
	h.Dispatch("login alice")
	out.Reset()

	h.Dispatch("mfa disable")

	if !strings.Contains(out.String(), "Usage") {
		t.Errorf("expected usage hint, got: %q", out.String())
	}
}
