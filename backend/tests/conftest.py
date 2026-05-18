import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app

SQLALCHEMY_TEST_URL = "sqlite:///./test_rtnotes.db"

engine = create_engine(
    SQLALCHEMY_TEST_URL,
    connect_args={"check_same_thread": False},
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    # Create tables that main.py normally creates inline
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
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


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
