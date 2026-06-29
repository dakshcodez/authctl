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
