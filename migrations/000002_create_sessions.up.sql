CREATE TABLE sessions (
    id         TEXT     PRIMARY KEY,
    user_id    TEXT     NOT NULL,
    token      TEXT     NOT NULL UNIQUE,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    expires_at DATETIME NOT NULL,
    is_active  INTEGER  NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_user_active ON sessions(user_id, is_active);
