-- Runs once, on first boot of an empty Postgres data volume.
-- Alembic owns the schema; this only guarantees the extension exists so the
-- first migration can declare vector columns (Chapter 3).
CREATE EXTENSION IF NOT EXISTS vector;
