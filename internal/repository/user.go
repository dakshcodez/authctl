package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/dakshcodez/authctl/internal/models"
)

var ErrNotFound = errors.New("not found")

type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	GetByID(ctx context.Context, id string) (*models.User, error)
	IncrementFailedAttempts(ctx context.Context, id string, at time.Time) error
	LockUntil(ctx context.Context, id string, until time.Time) error
	ResetFailedAttempts(ctx context.Context, id string) error
	UpdateLastLogin(ctx context.Context, id string, at time.Time) error
	EnableMFA(ctx context.Context, id string, encryptedSecret string) error
	// StoreTOTPSecret stores an encrypted TOTP secret without activating MFA.
	// Call ActivateMFA after the user verifies the first code.
	StoreTOTPSecret(ctx context.Context, id string, encryptedSecret string) error
	// ActivateMFA sets mfa_enabled=1 without changing the stored secret.
	ActivateMFA(ctx context.Context, id string) error
	// DisableMFA clears mfa_enabled and wipes the stored secret.
	DisableMFA(ctx context.Context, id string) error
}

type sqliteUserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
	return &sqliteUserRepository{db: db}
}

func (r *sqliteUserRepository) Create(ctx context.Context, user *models.User) error {
	const q = `
		INSERT INTO users (id, username, password_hash, mfa_enabled, encrypted_totp_secret,
		                   failed_attempts, last_failed_at, locked_until, registered_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.ExecContext(ctx, q,
		user.ID,
		user.Username,
		user.PasswordHash,
		boolToInt(user.MFAEnabled),
		user.EncryptedTOTPSecret,
		user.FailedAttempts,
		user.LastFailedAt,
		user.LockedUntil,
		user.RegisteredAt,
		user.LastLoginAt,
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (r *sqliteUserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	const q = `SELECT id, username, password_hash, mfa_enabled, encrypted_totp_secret,
	                  failed_attempts, last_failed_at, locked_until, registered_at, last_login_at
	           FROM users WHERE username = ?`
	row := r.db.QueryRowContext(ctx, q, username)
	return scanUser(row)
}

func (r *sqliteUserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	const q = `SELECT id, username, password_hash, mfa_enabled, encrypted_totp_secret,
	                  failed_attempts, last_failed_at, locked_until, registered_at, last_login_at
	           FROM users WHERE id = ?`
	row := r.db.QueryRowContext(ctx, q, id)
	return scanUser(row)
}

func (r *sqliteUserRepository) IncrementFailedAttempts(ctx context.Context, id string, at time.Time) error {
	const q = `UPDATE users SET failed_attempts = failed_attempts + 1, last_failed_at = ? WHERE id = ?`
	return execExpectOne(ctx, r.db, q, at, id)
}

func (r *sqliteUserRepository) LockUntil(ctx context.Context, id string, until time.Time) error {
	const q = `UPDATE users SET locked_until = ? WHERE id = ?`
	return execExpectOne(ctx, r.db, q, until, id)
}

func (r *sqliteUserRepository) ResetFailedAttempts(ctx context.Context, id string) error {
	const q = `UPDATE users SET failed_attempts = 0, last_failed_at = NULL, locked_until = NULL WHERE id = ?`
	return execExpectOne(ctx, r.db, q, id)
}

func (r *sqliteUserRepository) UpdateLastLogin(ctx context.Context, id string, at time.Time) error {
	const q = `UPDATE users SET last_login_at = ? WHERE id = ?`
	return execExpectOne(ctx, r.db, q, at, id)
}

func (r *sqliteUserRepository) EnableMFA(ctx context.Context, id string, encryptedSecret string) error {
	const q = `UPDATE users SET mfa_enabled = 1, encrypted_totp_secret = ? WHERE id = ?`
	return execExpectOne(ctx, r.db, q, encryptedSecret, id)
}

func (r *sqliteUserRepository) StoreTOTPSecret(ctx context.Context, id string, encryptedSecret string) error {
	const q = `UPDATE users SET encrypted_totp_secret = ? WHERE id = ?`
	return execExpectOne(ctx, r.db, q, encryptedSecret, id)
}

func (r *sqliteUserRepository) ActivateMFA(ctx context.Context, id string) error {
	const q = `UPDATE users SET mfa_enabled = 1 WHERE id = ?`
	return execExpectOne(ctx, r.db, q, id)
}

func (r *sqliteUserRepository) DisableMFA(ctx context.Context, id string) error {
	const q = `UPDATE users SET mfa_enabled = 0, encrypted_totp_secret = NULL WHERE id = ?`
	return execExpectOne(ctx, r.db, q, id)
}

// scanUser maps a sql.Row into a User, handling all nullable fields.
func scanUser(row *sql.Row) (*models.User, error) {
	var u models.User
	var mfaEnabled int
	var encryptedTOTPSecret sql.NullString
	var lastFailedAt sql.NullTime
	var lockedUntil sql.NullTime
	var lastLoginAt sql.NullTime

	err := row.Scan(
		&u.ID,
		&u.Username,
		&u.PasswordHash,
		&mfaEnabled,
		&encryptedTOTPSecret,
		&u.FailedAttempts,
		&lastFailedAt,
		&lockedUntil,
		&u.RegisteredAt,
		&lastLoginAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}

	u.MFAEnabled = mfaEnabled == 1
	if encryptedTOTPSecret.Valid {
		u.EncryptedTOTPSecret = &encryptedTOTPSecret.String
	}
	if lastFailedAt.Valid {
		u.LastFailedAt = &lastFailedAt.Time
	}
	if lockedUntil.Valid {
		u.LockedUntil = &lockedUntil.Time
	}
	if lastLoginAt.Valid {
		u.LastLoginAt = &lastLoginAt.Time
	}

	return &u, nil
}

// execExpectOne runs an UPDATE/DELETE and returns ErrNotFound if no rows were affected.
func execExpectOne(ctx context.Context, db *sql.DB, query string, args ...any) error {
	res, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
