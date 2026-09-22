# codesheriff-storage

Every database access in CodeSheriff. SQLAlchemy 2.0 models, one Alembic chain, and the
pgvector precedent store the context agent retrieves through.

Two rules govern this package.

**Nothing below it may import it.** `codesheriff_engine` — fusion and calibration — is forbidden
from importing `sqlalchemy` or this package at all, enforced by `lint-imports`. Fitted numbers must
be reproducible from the calibration split and a recorded corpus hash; a fusion module that can
open a session makes that an honour system (D-025).

**Source code is never stored.** `change_units` holds hashes and line metadata, never `post_src`.
Bounded excerpts are permitted only inside evidence artifacts and precedent chunks, capped at write
time by `redaction.py` (D-027).

## Layout

| Module | Holds |
|---|---|
| `models.py` | Every table. Contract invariants restated as CHECK constraints (D-026). |
| `mapping.py` | `ChangeUnit` / `Evidence` / `FusionResult` → rows. The only writer. |
| `redaction.py` | Excerpt budgets. Applied before anything reaches the database. |
| `precedents.py` | Nearest-neighbour retrieval over `precedent_chunks`. |
| `session.py` | Engine and session factory. Synchronous (D-028). |
| `migrations/` | The single Alembic chain. |

## Migrations

```bash
uv run alembic -c packages/storage/alembic.ini upgrade head
uv run alembic -c packages/storage/alembic.ini downgrade base
uv run alembic -c packages/storage/alembic.ini revision -m "..." --autogenerate
```

## Tests that need a database

Tests touching Postgres carry `@pytest.mark.db` and are **skipped unless
`CODESHERIFF_TEST_DB` is set** (D-029), so `uv run pytest` stays green on a machine with no
services running:

```bash
docker compose up -d postgres
CODESHERIFF_TEST_DB=postgresql+psycopg://codesheriff:codesheriff@localhost:5432/codesheriff_test \
  uv run pytest packages/storage -m db
```
