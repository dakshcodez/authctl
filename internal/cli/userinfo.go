package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/dakshcodez/authctl/internal/models"
)

const fieldWidth = 20

// renderLoginPanel shows the post-login summary.
// user must be the snapshot taken BEFORE UpdateLastLogin ran, so LastLoginAt
// is the previous login time, not the one just created.
func renderLoginPanel(out io.Writer, user *models.User, sessionExp time.Time) {
	divider(out)
	colorHeader.Fprintln(out, "Login Successful")
	fmt.Fprintln(out)
	colorHeader.Fprintln(out, "User Details")
	fmt.Fprintln(out)
	renderFields(out, user, sessionExp)
	divider(out)
}

// renderWhoamiPanel shows the current session summary.
func renderWhoamiPanel(out io.Writer, user *models.User, sessionExp time.Time) {
	divider(out)
	colorHeader.Fprintln(out, "Current User")
	fmt.Fprintln(out)
	renderFields(out, user, sessionExp)
	divider(out)
}

func renderFields(out io.Writer, user *models.User, sessionExp time.Time) {
	field(out, "Username", user.Username)
	field(out, "Registered", formatDate(user.RegisteredAt))
	field(out, "MFA", mfaStatus(user.MFAEnabled))
	field(out, "Last Login", formatOptDate(user.LastLoginAt))
	field(out, "Session Expires", formatDate(sessionExp))
	fmt.Fprintln(out)
}

func field(out io.Writer, label, value string) {
	fmt.Fprintf(out, "  %-*s: %s\n", fieldWidth, label, value)
}

func formatDate(t time.Time) string {
	return t.Local().Format("2006-01-02 15:04")
}

func formatOptDate(t *time.Time) string {
	if t == nil {
		return "Never"
	}
	return formatDate(*t)
}

func mfaStatus(enabled bool) string {
	if enabled {
		return colorSuccess.Sprint("Enabled")
	}
	return colorWarning.Sprint("Disabled")
}
