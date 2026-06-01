import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("UPLOAD_ROOT", tempfile.mkdtemp(prefix="rootnotes_test_"))

from app.core.enums import UserRole
from app.core.security import hash_password
from app.core.utils import new_id, ts_now
from app.database import Base, get_db
from app.main import app
from app.models.auth import User

SQLALCHEMY_TEST_URL = "sqlite://"

engine = create_engine(
    SQLALCHEMY_TEST_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

_override_stack = []


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    # Background tasks (e.g. run_queued_job) open their own session via
    # SessionLocal instead of the get_db dependency, so the dependency override
    # alone doesn't redirect them to the test DB. Rebind SessionLocal in every
    # namespace that imported it directly so those tasks hit the in-memory DB.
    import app.database as _database

    _database.SessionLocal = TestingSessionLocal
    try:
        import app.core.job_runner as _job_runner

        _job_runner.SessionLocal = TestingSessionLocal
    except (ImportError, AttributeError):
        pass

    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS global_settings "
            "(key TEXT PRIMARY KEY, value JSONB NOT NULL DEFAULT '{}')"
        ))
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_hosts_pid_ip
                ON hosts (pid, ip) WHERE ip IS NOT NULL AND ip <> '';
        """))
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_creds_pid_user_domain_host
                ON creds (pid, username, COALESCE(domain, ''), COALESCE(host, ''))
                WHERE username IS NOT NULL AND username <> '';
        """))
    _session = TestingSessionLocal()
    if not _session.query(User).filter_by(username="admin").first():
        _session.add(User(
            id=new_id("u"),
            username="admin",
            display_name="admin",
            password_hash=hash_password("TestPass1234!"),
            role=UserRole.ADMIN,
            created_at=ts_now(),
            active=True,
        ))
        _session.commit()
    _session.close()
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

    _prev = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    if _prev is None:
        app.dependency_overrides.pop(get_db, None)
    else:
        app.dependency_overrides[get_db] = _prev


@pytest.fixture(scope="module")
def module_db():
    session = TestingSessionLocal()
    admin = session.query(User).filter_by(username="admin").first()
    if admin:
        admin.password_hash = hash_password("TestPass1234!")
        admin.mfa_enabled = False
        admin.totp_secret = None
    else:
        session.add(User(
            id=new_id("u"),
            username="admin",
            display_name="admin",
            password_hash=hash_password("TestPass1234!"),
            role=UserRole.ADMIN,
            created_at=ts_now(),
            active=True,
        ))
    session.commit()
    yield session
    session.close()


@pytest.fixture(scope="module")
def module_client(module_db):
    def override_get_db():
        if not module_db.is_active:
            module_db.rollback()
        yield module_db

    _override_stack.append(override_get_db)
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    _override_stack.pop()
    if _override_stack:
        app.dependency_overrides[get_db] = _override_stack[-1]
    else:
        app.dependency_overrides.pop(get_db, None)
