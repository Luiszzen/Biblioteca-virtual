CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    full_name TEXT,
    turno TEXT
    grado INTEGER,
    seccion TEXT
);

CREATE TABLE books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    author TEXT,
    publisher TEXT,
    year INTEGER,
    isbn TEXT,
    language TEXT,
    category TEXT,
    status TEXT NOT NULL DEFAULT 'available'
);

CREATE TABLE loans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    book_id INTEGER NOT NULL REFERENCES books(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    borrowed_at TEXT NOT NULL,
    returned_at TEXT           
);

CREATE TABLE requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'pending',
    book_id INTEGER REFERENCES books(id),
    loan_id INTEGER REFERENCES loans(id),
    title TEXT,
    author TEXT,
    publisher TEXT,
    year INTEGER,
    isbn TEXT,
    language TEXT,
    category TEXT,
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    reviewed_by INTEGER REFERENCES users(id)
);

CREATE TABLE book_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    book_id INTEGER NOT NULL REFERENCES books(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    reason TEXT NOT NULL,
    details TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by INTEGER REFERENCES users(id)
);

CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    attempted_at TEXT NOT NULL
);

CREATE INDEX idx_loans_book ON loans(book_id);
CREATE INDEX idx_loans_user ON loans(user_id);
CREATE INDEX idx_login_attempts_user ON login_attempts(username, attempted_at);