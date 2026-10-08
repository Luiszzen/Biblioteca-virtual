-- Correr UNA sola vez por base de datos
ALTER TABLE users ADD COLUMN full_name TEXT;
ALTER TABLE users ADD COLUMN turno TEXT;
ALTER TABLE users ADD COLUMN grado INTEGER;
ALTER TABLE users ADD COLUMN seccion TEXT;