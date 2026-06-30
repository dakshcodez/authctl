package repository_test

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}

	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		t.Fatalf("enable foreign keys: %v", err)
	}

	schema := `
	CREATE TABLE users (
		id                    TEXT     PRIMARY KEY,
		username              TEXT     NOT NULL UNIQUE,
		password_hash         TEXT     NOT NULL,
		mfa_enabled           INTEGER  NOT NULL DEFAULT 0 CHECK (mfa_enabled IN (0, 1)),
		encrypted_totp_secret TEXT,
		failed_attempts       INTEGER  NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
		last_failed_at        DATETIME,
		locked_until          DATETIME,
		registered_at         DATETIME NOT NULL DEFAULT (datetime('now')),
		last_login_at         DATETIME
	);

	CREATE TABLE sessions (
		id         TEXT     PRIMARY KEY,
		user_id    TEXT     NOT NULL,
		token      TEXT     NOT NULL UNIQUE,
		created_at DATETIME NOT NULL DEFAULT (datetime('now')),
		expires_at DATETIME NOT NULL,
		is_active  INTEGER  NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);`

	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	t.Cleanup(func() { db.Close() })
	return db
}
