# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""ISO 8601 -> epoch milliseconds, matching JavaScript's Date.parse for our uses."""
from datetime import datetime, timezone


def parse_iso_ms(ts):
    """Return epoch milliseconds for an ISO 8601 string, or None if unparseable."""
    if not isinstance(ts, str):
        return None
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)
