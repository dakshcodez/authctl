package main

import (
	"log/slog"
	"os"
	"path/filepath"

	rl "github.com/chzyer/readline"

	"github.com/dakshcodez/authctl/internal/cli"
	"github.com/dakshcodez/authctl/internal/config"
	"github.com/dakshcodez/authctl/internal/database"
	"github.com/dakshcodez/authctl/internal/logger"
	"github.com/dakshcodez/authctl/internal/repository"
	"github.com/dakshcodez/authctl/internal/service"
	"github.com/dakshcodez/authctl/internal/session"
	"github.com/dakshcodez/authctl/migrations"
)

func main() {
	cli.PrintBanner(os.Stdout)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	log := logger.New(cfg)

	cli.PrintStartupStatus(os.Stdout, "Initializing...")

	db, err := database.Connect(cfg, log)
	if err != nil {
		log.Error("connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	cli.PrintStartupStatus(os.Stdout, "Database connected.")

	if err := database.Migrate(db, migrations.FS, log); err != nil {
		log.Error("run migrations", "error", err)
		os.Exit(1)
	}
	cli.PrintStartupStatus(os.Stdout, "Database migrations applied.")

	users := repository.NewUserRepository(db)
	sessions := repository.NewSessionRepository(db)
	auth := service.NewAuthService(users, sessions, cfg, log)

	sessionPath, err := session.DefaultPath()
	if err != nil {
		log.Error("resolve session path", "error", err)
		os.Exit(1)
	}
	store := session.NewFileStore(sessionPath)

	historyFile := filepath.Join(filepath.Dir(sessionPath), "history")

	readline, err := rl.NewEx(&rl.Config{
		Prompt:          cli.DefaultPrompt(),
		HistoryFile:     historyFile,
		AutoComplete:    buildCompleter(),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		log.Error("init readline", "error", err)
		os.Exit(1)
	}
	defer readline.Close()

	prompter := cli.NewReadlinePrompter(readline)
	handler := cli.NewHandler(auth, store, os.Stdout, prompter)

	// Sync prompt to any session persisted from a previous run.
	handler.Init()

	cli.PrintReady(os.Stdout)

	shell := cli.NewShellFromReadline(readline, handler)
	if err := shell.Run(); err != nil {
		log.Error("shell error", "error", err)
		os.Exit(1)
	}
}

func buildCompleter() *rl.PrefixCompleter {
	return rl.NewPrefixCompleter(
		rl.PcItem("register"),
		rl.PcItem("login"),
		rl.PcItem("logout"),
		rl.PcItem("whoami"),
		rl.PcItem("help"),
		rl.PcItem("exit"),
	)
}
