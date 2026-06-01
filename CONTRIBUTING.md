# Contributing to RootNotes

## Prerequisites

- Docker + Docker Compose v2
- Python 3.11+ (for backend development outside containers)
- Node.js 20+ (for frontend development outside containers)
- Git

## Local setup

1. Copy the environment file and adjust values if needed:

```bash
cp .env.example .env
```

2. Build and start the full stack:

```bash
docker compose up -d --build
```

3. The app will be available at `http://localhost` (nginx proxy).  
   On first run, the setup wizard creates the initial admin account.

## Development workflow

All feature work must follow the branch model from [docs/modules/WORKFLOW_RULES.md](docs/modules/WORKFLOW_RULES.md).

Short version:

```
feature/<name>  →  dev  →  main (owner-only)
```

1. Create a branch from `dev`:

```bash
git checkout dev
git checkout -b feature/my-feature
```

2. Make your changes.

3. Validate with a full container rebuild:

```bash
docker compose up -d --build
```

4. Run backend linting:

```bash
cd backend
pip install ruff black
ruff check app
black --check app
```

5. Run frontend linting and build:

```bash
cd frontend
npm ci
npm run lint
npm run build
```

6. If the feature has a user-visible effect, document it in [docs/modules/HANDS_ON.md](docs/modules/HANDS_ON.md) — see the format in that file.

7. Merge into `dev`:

```bash
git checkout dev
git merge --no-ff feature/my-feature
```

## Code conventions

### Backend (Python)

- Formatter: **black** (line length 100)
- Linter: **ruff**
- Config: `backend/pyproject.toml`
- Errors: use `AppError` from `core/errors.py` for new endpoints
- Logging: use `get_logger(__name__)` from `core/logging_setup.py`; no bare `print()`
- Enums: use `core/enums.py` types for roles and severity; no magic strings

### Frontend (JavaScript/JSX)

- Linter: **eslint** (flat config in `frontend/eslint.config.js`)
- Run: `npm run lint`
- No bare `console.log` in production code (`console.warn` and `console.error` are allowed)
- Domain data hooks: use `src/hooks/useProjectData.js` instead of calling `api.*` directly in components when doing standard list fetches

## Pre-commit hooks (optional)

Install [pre-commit](https://pre-commit.com/) to run checks automatically before every commit:

```bash
pip install pre-commit
pre-commit install
```

Config: `.pre-commit-config.yaml` at the repo root.

## Database migrations

Schema changes must be captured in an Alembic migration file. Never alter the
schema by hand or by editing existing migrations.

### Adding a migration

```bash
cd backend

# 1. Edit app/models/<domain>.py — add the new column or table to the ORM class

# 2. Generate a migration (autogenerate compares models vs. live DB):
make db-new MSG="add last_login_at to users"

# 3. Review the generated file in alembic/versions/ and verify both
#    upgrade() and downgrade() are correct

# 4. Apply locally to confirm:
make db-upgrade
```

### Migration style guide

- Use `op.add_column()`, `op.create_table()`, `op.drop_column()` etc. (Alembic ops)
  rather than raw `op.execute(text(...))` for structural changes.
- Always implement `downgrade()`. For irreversible data migrations, add a comment
  explaining why rollback is not possible and raise `NotImplementedError` so it
  fails loudly.
- Keep each migration focused: one logical change per file.
- Test both directions: `make db-upgrade` then `make db-downgrade` then `make db-upgrade` again.

### Common make targets (from `backend/`)

| Command | Action |
|---------|--------|
| `make db-status` | Show current migration version |
| `make db-upgrade` | Apply all pending migrations |
| `make db-downgrade` | Roll back one step |
| `make db-new MSG="..."` | Generate migration from model changes |
| `make db-history` | Show full migration chain |

## Tests

Backend tests live in `backend/tests/`. Run inside the container:

```bash
docker compose exec -w /app backend python -m pytest tests/ -v
```

For a fresh isolated DB (recommended for CI):

```bash
docker compose exec backend python -m pytest tests/ --tb=short
```

Or use the dedicated test image (SQLite, no external services required):

```bash
docker build -t rtnotes-test -f backend/Dockerfile.test backend/
docker run --rm rtnotes-test pytest tests/ -q
```
