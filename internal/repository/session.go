package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/dakshcodez/authctl/internal/models"
)

type SessionRepository interface {
	Create(ctx context.Context, session *models.Session) error
	GetByToken(ctx context.Context, token string) (*models.Session, error)
	Invalidate(ctx context.Context, id string) error
	InvalidateAllForUser(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context) error
}

type sqliteSessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) SessionRepository {
	return &sqliteSessionRepository{db: db}
}

// hashToken stores a SHA-256 hash of the token so a DB breach cannot replay sessions.
// Tokens are high-entropy random values, making SHA-256 appropriate here.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (r *sqliteSessionRepository) Create(ctx context.Context, session *models.Session) error {
	const q = `
		INSERT INTO sessions (id, user_id, token, created_at, expires_at, is_active)
		VALUES (?, ?, ?, ?, ?, ?)`

	_, err := r.db.ExecContext(ctx, q,
		session.ID,
		session.UserID,
		hashToken(session.Token),
		session.CreatedAt,
		session.ExpiresAt,
		boolToInt(session.IsActive),
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (r *sqliteSessionRepository) GetByToken(ctx context.Context, token string) (*models.Session, error) {
	const q = `
		SELECT id, user_id, token, created_at, expires_at, is_active
		FROM sessions WHERE token = ?`

	row := r.db.QueryRowContext(ctx, q, hashToken(token))

	var s models.Session
	var isActive int

	err := row.Scan(&s.ID, &s.UserID, &s.Token, &s.CreatedAt, &s.ExpiresAt, &isActive)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}

	s.IsActive = isActive == 1
	// Return the hash stored in DB, not the plaintext — callers must not compare with raw token.
	return &s, nil
}

func (r *sqliteSessionRepository) Invalidate(ctx context.Context, id string) error {
	const q = `UPDATE sessions SET is_active = 0 WHERE id = ?`
	return execExpectOne(ctx, r.db, q, id)
}

func (r *sqliteSessionRepository) InvalidateAllForUser(ctx context.Context, userID string) error {
	const q = `UPDATE sessions SET is_active = 0 WHERE user_id = ? AND is_active = 1`
	_, err := r.db.ExecContext(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("invalidate user sessions: %w", err)
	}
	return nil
}

func (r *sqliteSessionRepository) DeleteExpired(ctx context.Context) error {
	const q = `DELETE FROM sessions WHERE expires_at < datetime('now')`
	_, err := r.db.ExecContext(ctx, q)
	if err != nil {
		return fmt.Errorf("delete expired sessions: %w", err)
	}
	return nil
}
