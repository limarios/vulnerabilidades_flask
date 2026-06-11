"""Flask extensions, instantiated once and initialized inside the factory."""

from __future__ import annotations

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Created here, bound to an app inside create_app(). Default limits are deliberately
# absent: the vulnerable routes must stay unprotected, so limits are applied
# explicitly on the secure routes only.
limiter = Limiter(key_func=get_remote_address)
