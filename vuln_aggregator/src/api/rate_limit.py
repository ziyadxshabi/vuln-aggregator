"""Rate limiting configuration.

Limits how many requests a single client IP can make per minute, reducing
credential-stuffing risk on auth and protecting the API from abuse.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Default cap for authenticated/read routes; auth token uses a stricter override.
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])
