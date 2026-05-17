"""
Pytest setup — uses a dedicated PostgreSQL database (`rtnotes_test`).

We can't fall back to SQLite because several models use `ARRAY(String)`
(`hosts.ports`, `creds.host_ids`, `notes.tags`, ...) which SQLite's type
compiler can't render. The compose stack already runs Postgres, so tests
run inside the backend container point at the `rtnotes_test` DB on the
same instance.

Each test gets its own session inside a SAVEPOINT-style rollback so
fixtures don't leak between cases.
"""
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app

# Disable rate limiting during tests — B4-1 caps /api/auth/login to 5/minute,
# which breaks any suite that authenticates more than 5 times per run.
from app.core.limiter import limiter
limiter.enabled = False

DEFAULT_TEST_URL = "postgresql://rtnotes:rtnotes_secret@db:5432/rtnotes_test"
SQLALCHEMY_TEST_URL = os.environ.get("TEST_DATABASE_URL", DEFAULT_TEST_URL)

engine = create_engine(SQLALCHEMY_TEST_URL, future=True)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS global_settings "
            "(key TEXT PRIMARY KEY, value JSONB NOT NULL DEFAULT '{}')"
        ))
        # Migration 006 partial unique indexes — required by the race-safe
        # upsert tests (try_insert_or_get only trips IntegrityError when
        # the underlying constraint exists).
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_hosts_pid_ip
                ON hosts (pid, ip) WHERE ip IS NOT NULL AND ip <> '';
        """))
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_creds_pid_user_domain_host
                ON creds (pid, username, COALESCE(domain, ''), COALESCE(host, ''))
                WHERE username IS NOT NULL AND username <> '';
        """))
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    """
    Session per test, rolled back on teardown.

    `join_transaction_mode="create_savepoint"` turns every `session.commit()`
    into a SAVEPOINT release within the outer connection-level transaction.
    Without this, route handlers that call `db.commit()` would consume the
    outer transaction and the final `rollback()` would no-op — letting state
    bleed between tests.
    """
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(
        bind=connection,
        join_transaction_mode="create_savepoint",
    )
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture()
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()
