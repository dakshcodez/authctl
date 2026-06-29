package logger

import (
	"log/slog"
	"os"

	"github.com/dakshcodez/authctl/internal/config"
)

type Logger struct {
	*slog.Logger
}

func New(cfg *config.Config) *Logger {
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
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
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