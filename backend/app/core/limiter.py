import os

from slowapi import Limiter
from slowapi.util import get_remote_address

_enabled = os.environ.get("APP_ENV", "dev").lower() not in ("test", "testing")
limiter = Limiter(key_func=get_remote_address, enabled=_enabled)
