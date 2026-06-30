package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mdp/qrterminal/v3"

	"github.com/dakshcodez/authctl/internal/service"
	"github.com/dakshcodez/authctl/internal/session"
)

// Handler dispatches CLI commands to the auth service.
// All output is written to out; password/line input comes through prompter.
// Both are injectable for testing without a terminal.
type Handler struct {
	auth     service.AuthService
	store    session.Store
	out      io.Writer
	prompter Prompter
}

// Prompter abstracts terminal input and prompt control so both can be faked in tests.
type Prompter interface {
	ReadPassword(prompt string) (string, error)
	ReadLine(prompt string) (string, error)
	SetPrompt(prompt string)
}

func NewHandler(auth service.AuthService, store session.Store, out io.Writer, prompter Prompter) *Handler {
	return &Handler{auth: auth, store: store, out: out, prompter: prompter}
}

// Init syncs the prompt to the stored session on startup.
func (h *Handler) Init() {
	if stored, err := h.store.Load(); err == nil {
		h.prompter.SetPrompt(UserPrompt(stored.Username))
	}
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
	case "mfa":
		err = h.mfa(args)
	case "clear":
		fmt.Fprint(h.out, "\033[H\033[2J")
	case "help":
		h.help()
	default:
		warn(h.out, "unknown command: %s (type 'help' for commands)", cmd)
	}

	if err != nil {
		if errors.Is(err, ErrInterrupted) {
			fmt.Fprintln(h.out) // newline after ^C so the next prompt starts clean
			return
		}
		fail(h.out, "error: %s", h.userMessage(err))
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
	case errors.Is(err, service.ErrInvalidMFACode):
		return "invalid MFA code"
	case errors.Is(err, service.ErrMFANotEnabled):
		return "MFA is not enabled on this account"
	case errors.Is(err, service.ErrMFAAlreadyEnabled):
		return "MFA is already enabled on this account"
	case errors.Is(err, service.ErrTOTPNotConfigured):
		return "run 'mfa setup' before enabling MFA"
	case errors.Is(err, service.ErrMFAUnavailable):
		return "MFA is unavailable — server is not configured with a TOTP encryption key"
	default:
		return err.Error()
	}
}

func (h *Handler) register(args []string) error {
	if stored, err := h.store.Load(); err == nil {
		warn(h.out, "You are logged in as %s. Please logout before registering a new account.", stored.Username)
		return nil
	}

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

	success(h.out, "Registered successfully as %s", user.Username)
	return nil
}

func (h *Handler) login(args []string) error {
	// Prevent double login: check for an existing valid session first.
	if stored, err := h.store.Load(); err == nil {
		warn(h.out, "You are already logged in as %s. Please logout first.", stored.Username)
		return nil
	}

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

	result, err := h.auth.Login(context.Background(), username, password)
	if errors.Is(err, service.ErrMFARequired) {
		result, err = h.loginMFAStep(username, password)
	}
	if err != nil {
		return err
	}

	return h.completeLogin(username, result)
}

// loginMFAStep prompts for a TOTP code and calls LoginWithMFA.
func (h *Handler) loginMFAStep(username, password string) (*service.LoginResult, error) {
	warn(h.out, "MFA is enabled on this account.")
	code, err := h.prompter.ReadLine("TOTP code: ")
	if err != nil {
		return nil, err
	}
	return h.auth.LoginWithMFA(context.Background(), username, password, strings.TrimSpace(code))
}

// completeLogin saves the session and updates the prompt after a successful login.
func (h *Handler) completeLogin(username string, result *service.LoginResult) error {
	stored := &session.StoredSession{
		Token:     result.Session.Token,
		Username:  username,
		ExpiresAt: result.Session.ExpiresAt,
	}
	if err := h.store.Save(stored); err != nil {
		return fmt.Errorf("save session: %w", err)
	}

	// Update prompt to reflect the authenticated user.
	h.prompter.SetPrompt(UserPrompt(username))

	// Show previous login time from the user snapshot (before UpdateLastLogin ran).
	renderLoginPanel(h.out, result.User, result.Session.ExpiresAt)
	return nil
}

func (h *Handler) logout() error {
	stored, err := h.store.Load()
	if errors.Is(err, session.ErrNoSession) {
		warn(h.out, "Not logged in.")
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

	// Revert prompt to unauthenticated state.
	h.prompter.SetPrompt(DefaultPrompt())

	success(h.out, "Logged out.")
	return nil
}

func (h *Handler) whoami() error {
	stored, err := h.store.Load()
	if errors.Is(err, session.ErrNoSession) {
		warn(h.out, "Not logged in.")
		return nil
	}
	if err != nil {
		return err
	}

	user, err := h.auth.ValidateSession(context.Background(), stored.Token)
	if err != nil {
		h.store.Clear()
		h.prompter.SetPrompt(DefaultPrompt())
		warn(h.out, "Session expired — please login again.")
		return nil
	}

	renderWhoamiPanel(h.out, user, stored.ExpiresAt)
	return nil
}

func (h *Handler) mfa(args []string) error {
	if len(args) == 0 {
		warn(h.out, "Usage: mfa <setup|enable <code>|disable <code>>")
		return nil
	}

	stored, err := h.store.Load()
	if errors.Is(err, session.ErrNoSession) {
		warn(h.out, "Not logged in.")
		return nil
	}
	if err != nil {
		return err
	}

	user, err := h.auth.ValidateSession(context.Background(), stored.Token)
	if err != nil {
		h.store.Clear()
		h.prompter.SetPrompt(DefaultPrompt())
		warn(h.out, "Session expired — please login again.")
		return nil
	}

	switch args[0] {
	case "setup":
		return h.mfaSetup(user.ID)
	case "enable":
		if len(args) < 2 {
			warn(h.out, "Usage: mfa enable <6-digit code>")
			return nil
		}
		return h.mfaEnable(user.ID, args[1])
	case "disable":
		if len(args) < 2 {
			warn(h.out, "Usage: mfa disable <6-digit code>")
			return nil
		}
		return h.mfaDisable(user.ID, args[1])
	default:
		warn(h.out, "Unknown mfa subcommand: %s (setup, enable, disable)", args[0])
		return nil
	}
}

func (h *Handler) mfaSetup(userID string) error {
	result, err := h.auth.SetupMFA(context.Background(), userID)
	if err != nil {
		return err
	}

	colorHeader.Fprintln(h.out, "MFA Setup")
	fmt.Fprintln(h.out, "")
	colorDim.Fprintln(h.out, "  Scan with Google Authenticator, Authy, 1Password, etc.:")
	fmt.Fprintln(h.out, "")

	qrterminal.GenerateWithConfig(result.ProviderURI, qrterminal.Config{
		Level:      qrterminal.L,
		Writer:     h.out,
		HalfBlocks: true,
		BlackChar:  qrterminal.BLACK_BLACK,
		WhiteChar:  qrterminal.WHITE_WHITE,
	})

	fmt.Fprintln(h.out, "")
	colorDim.Fprintf(h.out, "  Can't scan? Enter this key manually: ")
	fmt.Fprintln(h.out, result.Secret)
	fmt.Fprintln(h.out, "")
	colorDim.Fprintln(h.out, "  Then run: mfa enable <6-digit code>")
	fmt.Fprintln(h.out, "")
	return nil
}

func (h *Handler) mfaEnable(userID, code string) error {
	if err := h.auth.VerifyAndEnableMFA(context.Background(), userID, code); err != nil {
		return err
	}
	success(h.out, "MFA enabled. Your account now requires a TOTP code at login.")
	return nil
}

func (h *Handler) mfaDisable(userID, code string) error {
	if err := h.auth.DisableMFA(context.Background(), userID, code); err != nil {
		return err
	}
	success(h.out, "MFA disabled.")
	return nil
}

func (h *Handler) help() {
	colorHeader.Fprintln(h.out, "Available commands:")
	fmt.Fprintln(h.out, "")
	fmt.Fprintln(h.out, "  register [username]        Create a new account")
	fmt.Fprintln(h.out, "  login [username]           Log in to your account")
	fmt.Fprintln(h.out, "  logout                     End your current session")
	fmt.Fprintln(h.out, "  whoami                     Show current session info")
	fmt.Fprintln(h.out, "  mfa setup                  Generate a TOTP secret")
	fmt.Fprintln(h.out, "  mfa enable <code>          Activate MFA after setup")
	fmt.Fprintln(h.out, "  mfa disable <code>         Deactivate MFA")
	fmt.Fprintln(h.out, "  clear                      Clear the screen")
	fmt.Fprintln(h.out, "  help                       Show this help")
	fmt.Fprintln(h.out, "  exit                       Quit")
	fmt.Fprintln(h.out, "")
}
