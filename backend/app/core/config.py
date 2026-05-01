import os
import re
from pathlib import Path

JWT_SECRET = os.environ.get("JWT_SECRET", "redteam-notes-change-me-in-production")
JWT_ALGO = "HS256"
JWT_EXPIRE_HOURS = 24 * 7

UPLOAD_ROOT = Path(os.environ.get("UPLOAD_ROOT", "/data/uploads"))
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

SAFE_UPLOAD_RE = re.compile(r"[^A-Za-z0-9._-]+")
DEFAULT_CATALOG_PATH = Path(__file__).parent.parent / "default_catalog.json"
