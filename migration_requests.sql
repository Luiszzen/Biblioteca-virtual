-- migration_requests.sql
-- Correr una sola vez:  Get-Content migration_requests.sql | sqlite3 library.db

-- Marca qué usuarios son administradores
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;

-- Una fila por cada solicitud de acción (prestar, devolver, agregar libro)
CREATE TABLE requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,                        -- 'borrow', 'return', 'add_book'
    user_id INTEGER NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'pending',     -- 'pending', 'approved', 'rejected'

    -- usados por 'borrow'
    book_id INTEGER REFERENCES books(id),

    -- usado por 'return'
    loan_id INTEGER REFERENCES loans(id),

    -- usados solo por 'add_book' (el libro todavía no existe en books)
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

-- Vuélvete administrador (cambia 'luis' por tu username real)
-- UPDATE users SET is_admin = 1 WHERE username = 'luis';