package main

import (
	"log/slog"
	"os"

	"github.com/dakshcodez/authctl/internal/config"
	"github.com/dakshcodez/authctl/internal/database"
	"github.com/dakshcodez/authctl/internal/logger"
	"github.com/dakshcodez/authctl/migrations"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	log := logger.New(cfg)

	db, err := database.Connect(cfg, log)
	if err != nil {
		log.Error("connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := database.Migrate(db, migrations.FS, log); err != nil {
		log.Error("run migrations", "error", err)
		os.Exit(1)
	}
}
