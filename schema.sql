-- schema.sql
-- Run this once to create the database:
--   sqlite3 library.db < schema.sql
--
-- Three tables: users (accounts), books (catalog), loans (borrow history)

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL
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
    status TEXT NOT NULL DEFAULT 'available'  -- 'available' or 'borrowed'
);

CREATE TABLE loans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    book_id INTEGER NOT NULL REFERENCES books(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    borrowed_at TEXT NOT NULL,   -- ISO date string
    returned_at TEXT             -- NULL while the book is still out
);

CREATE INDEX idx_loans_book ON loans(book_id);
CREATE INDEX idx_loans_user ON loans(user_id);
