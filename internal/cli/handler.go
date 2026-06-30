package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/dakshcodez/authctl/internal/service"
	"github.com/dakshcodez/authctl/internal/session"
)

// Handler dispatches CLI commands to the auth service.
// It writes all output to out and reads passwords via prompter,
// both of which are injectable for testing.
type Handler struct {
	auth     service.AuthService
	store    session.Store
	out      io.Writer
	prompter Prompter
}

// Prompter abstracts masked password input so it can be faked in tests.
type Prompter interface {
	ReadPassword(prompt string) (string, error)
	ReadLine(prompt string) (string, error)
}

func NewHandler(auth service.AuthService, store session.Store, out io.Writer, prompter Prompter) *Handler {
	return &Handler{auth: auth, store: store, out: out, prompter: prompter}
}

func (h *Handler) Dispatch(input string) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return
	}

	cmd := parts[0]
	args := parts[1:]

	var err error
	switch cmd {
	case "register":
		err = h.register(args)
	case "login":
		err = h.login(args)
	case "logout":
		err = h.logout()
	case "whoami":
		err = h.whoami()
	case "help":
		h.help()
	default:
		fmt.Fprintf(h.out, "unknown command: %s (type 'help' for commands)\n", cmd)
	}

	if err != nil {
		fmt.Fprintf(h.out, "error: %s\n", h.userMessage(err))
	}
}

func (h *Handler) userMessage(err error) string {
	switch {
	case errors.Is(err, service.ErrInvalidCredentials):
		return "invalid username or password"
	case errors.Is(err, service.ErrAccountLocked):
		return "account is temporarily locked due to too many failed attempts"
	case errors.Is(err, service.ErrUserExists):
		return "username already taken"
	case errors.Is(err, service.ErrSessionNotFound):
		return "session not found or expired — please login again"
	case errors.Is(err, service.ErrMFARequired):
		return "MFA is enabled on this account (TOTP support coming in a future version)"
	default:
		return err.Error()
	}
}

func (h *Handler) register(args []string) error {
	var username string
	var err error

	if len(args) > 0 {
		username = args[0]
	} else {
		username, err = h.prompter.ReadLine("Username: ")
		if err != nil {
			return err
		}
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	password, err := h.prompter.ReadPassword("Password: ")
	if err != nil {
		return err
	}

	confirm, err := h.prompter.ReadPassword("Confirm password: ")
	if err != nil {
		return err
	}

	if password != confirm {
		return fmt.Errorf("passwords do not match")
	}

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	user, err := h.auth.Register(context.Background(), username, password)
	if err != nil {
		return err
	}

	fmt.Fprintf(h.out, "registered successfully as %s\n", user.Username)
	return nil
}

func (h *Handler) login(args []string) error {
	var username string
	var err error

	if len(args) > 0 {
		username = args[0]
	} else {
		username, err = h.prompter.ReadLine("Username: ")
		if err != nil {
			return err
		}
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	password, err := h.prompter.ReadPassword("Password: ")
	if err != nil {
		return err
	}

	sess, err := h.auth.Login(context.Background(), username, password)
	if err != nil {
		return err
	}

	stored := &session.StoredSession{
		Token:     sess.Token,
		Username:  username,
		ExpiresAt: sess.ExpiresAt,
	}
	if err := h.store.Save(stored); err != nil {
		return fmt.Errorf("save session: %w", err)
	}

	fmt.Fprintf(h.out, "logged in as %s\n", username)
	return nil
}

func (h *Handler) logout() error {
	stored, err := h.store.Load()
	if errors.Is(err, session.ErrNoSession) {
		fmt.Fprintln(h.out, "not logged in")
		return nil
	}
	if err != nil {
		return err
	}

	if err := h.auth.Logout(context.Background(), stored.Token); err != nil {
		return err
	}

	if err := h.store.Clear(); err != nil {
		return err
	}

	fmt.Fprintln(h.out, "logged out")
	return nil
}

func (h *Handler) whoami() error {
	stored, err := h.store.Load()
	if errors.Is(err, session.ErrNoSession) {
		fmt.Fprintln(h.out, "not logged in")
		return nil
	}
	if err != nil {
		return err
	}

	_, err = h.auth.ValidateSession(context.Background(), stored.Token)
	if err != nil {
		h.store.Clear()
		fmt.Fprintln(h.out, "session expired — please login again")
		return nil
	}

	fmt.Fprintf(h.out, "logged in as %s (session expires %s)\n",
		stored.Username,
		stored.ExpiresAt.Local().Format("2006-01-02 15:04:05"),
	)
	return nil
}

func (h *Handler) help() {
	fmt.Fprintln(h.out, `commands:
  register [username]   create a new account
  login [username]      log in to your account
  logout                end your current session
  whoami                show current session info
  help                  show this help
  exit                  quit`)
}
