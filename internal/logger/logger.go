package logger

import (
	"io"
	"log/slog"

	"github.com/dakshcodez/authctl/internal/config"
)

type Logger struct {
	*slog.Logger
}

func New(cfg *config.Config, w io.Writer) *Logger {
	var level slog.Level

	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler

	if cfg.AppEnv == "production" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	return &Logger{
		Logger: slog.New(handler),
	}
}

// Audit logs authentication and business events.
func (l *Logger) Audit(msg string, args ...any) {
	args = append([]any{
		slog.String("category", "audit"),
	}, args...)

	l.Info(msg, args...)
}

// Security logs suspicious or security-related events.
func (l *Logger) Security(msg string, args ...any) {
	args = append([]any{
		slog.String("category", "security"),
	}, args...)

	l.Warn(msg, args...)
}