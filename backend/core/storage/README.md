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
| `models.py` | Every table. Contract invariants restated as CHECK constraints (D-026). Includes Better Auth's tables (`users`, `auth_*`), which Python declares but never writes (D-101). |
| `mapping.py` | `ChangeUnit` / `Evidence` / `FusionResult` → rows. The only writer of analysis rows. |
| `audits.py` | The audit lifecycle: open, claim, supersede, finish, fail. Single conditional UPDATEs, so two workers cannot race. |
| `identity.py` | Installations and repositories: upserts from GitHub, the scoped repository list, and hiding on uninstall or deselection (D-102). |
| `reporting.py` | Every dashboard read. Each takes `installation_ids` and returns nothing when it is empty (D-035), and skips hidden repositories (D-102). |
| `redaction.py` | Excerpt budgets. Applied before anything reaches the database. |
| `precedents.py` | Nearest-neighbour retrieval over `precedent_chunks`. |
| `session.py` | Engine and session factory. Synchronous (D-028). |
| `testing.py` | Migrate-and-roll-back fixtures shared with `backend/api`'s tests. |
| `migrations/` | The single Alembic chain, including Better Auth's tables (`0006`) and the hide-not-delete columns (`0007`). Never `npx auth migrate`. |

**Nothing about an installation or repository is deleted when GitHub withdraws it** (D-102):
`installations.uninstalled_at` and `repositories.removed_at` are set instead, and every scoped
query filters `removed_at IS NULL`. A new dashboard query must add that filter beside
`installation_id.in_(...)`, or it shows disconnected data.

## Migrations

```bash
uv run alembic -c backend/core/storage/alembic.ini upgrade head
uv run alembic -c backend/core/storage/alembic.ini downgrade base
uv run alembic -c backend/core/storage/alembic.ini revision -m "..." --autogenerate
```

## Tests that need a database

Tests touching Postgres carry `@pytest.mark.db` and are **skipped unless
`CODESHERIFF_TEST_DB` is set** (D-029), so `uv run pytest` stays green on a machine with no
services running. They migrate that database down to empty before and after, so it must be a
separate database, never the one holding real audits:

```bash
docker compose up -d postgres
docker exec codesheriff-postgres psql -U codesheriff -c "create database codesheriff_test"
CODESHERIFF_TEST_DB=postgresql+psycopg://codesheriff:codesheriff@localhost:5432/codesheriff_test \
  uv run pytest backend/core/storage -m db
```
