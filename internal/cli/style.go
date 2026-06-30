package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
)

// Palette — use these everywhere instead of raw color calls.
var (
	colorSuccess = color.New(color.FgGreen)
	colorError   = color.New(color.FgRed)
	colorWarning = color.New(color.FgYellow)
	colorHeader  = color.New(color.FgCyan, color.Bold)
	colorBanner  = color.New(color.FgCyan)
	colorDim     = color.New(color.Faint)
)

const dividerLen = 50

// Divider prints a horizontal rule.
func divider(out io.Writer) {
	colorDim.Fprintln(out, strings.Repeat("-", dividerLen))
}

// success/warn/fail write a styled line to out.
func success(out io.Writer, format string, a ...any) {
	colorSuccess.Fprintf(out, format+"\n", a...)
}

func warn(out io.Writer, format string, a ...any) {
	colorWarning.Fprintf(out, format+"\n", a...)
}

func fail(out io.Writer, format string, a ...any) {
	colorError.Fprintf(out, format+"\n", a...)
}

// DefaultPrompt returns the cyan "authctl> " readline-safe string.
func DefaultPrompt() string {
	return promptWrap("\033[36m", "authctl") + "> "
}

// UserPrompt returns the green "authctl(username)> " readline-safe string.
func UserPrompt(username string) string {
	return promptWrap("\033[32m", fmt.Sprintf("authctl(%s)", username)) + "> "
}

// promptWrap surrounds ANSI codes in \001\002 so readline calculates
// the visible width correctly when the cursor wraps or history is recalled.
func promptWrap(ansiCode, text string) string {
	if color.NoColor {
		return text
	}
	return "\001" + ansiCode + "\002" + text + "\001\033[0m\002"
}
