# Database migration helpers
# Requires DATABASE_URL env var or docker-compose db service to be running.
#
# Usage:
#   make db-status          — show current migration version
#   make db-upgrade         — apply all pending migrations
#   make db-downgrade       — roll back one step
#   make db-new MSG="..."   — generate a new migration from model changes
#   make db-history         — show full migration chain

DATABASE_URL ?= postgresql://rtnotes:rtnotes@localhost:5432/rtnotes

.PHONY: db-status db-upgrade db-downgrade db-new db-history

db-status:
	DATABASE_URL=$(DATABASE_URL) alembic current

db-upgrade:
	DATABASE_URL=$(DATABASE_URL) alembic upgrade head

db-downgrade:
	DATABASE_URL=$(DATABASE_URL) alembic downgrade -1

db-new:
	@test -n "$(MSG)" || (echo "Usage: make db-new MSG='describe the change'" && exit 1)
	DATABASE_URL=$(DATABASE_URL) alembic revision --autogenerate -m "$(MSG)"

db-history:
	DATABASE_URL=$(DATABASE_URL) alembic history --verbose
