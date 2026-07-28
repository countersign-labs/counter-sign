# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
Hash-chained receipt log — matches src/receipt-log.ts.

Each entry is ``{seq, prev, receipt}`` (0-based ``seq``; ``prev`` is the previous
entry's hash, the genesis anchor for ``seq`` 0). An entry's hash is
``base64url(sha256(utf8(canonical(entry))))``. ``head()`` is the last entry's hash
(or the genesis anchor for an empty log) plus the length, for external anchoring.
"""
import hashlib

from .canonical import canonicalize
from .constants import CHAIN_GENESIS_LABEL
from .keys import b64url_encode, utf8


def _sha256_b64url(s: str) -> str:
    return b64url_encode(hashlib.sha256(utf8(s)).digest())


#: The chain's genesis ``prev``: a fixed, version-domain-separated anchor.
CHAIN_GENESIS = _sha256_b64url(CHAIN_GENESIS_LABEL)


def entry_hash(entry) -> str:
    """The link hash of one entry: base64url SHA-256 over its canonical JSON."""
    return _sha256_b64url(canonicalize(entry))


class ReceiptLog:
    """An in-memory append-only chained log. Mirrors the reference's chain semantics."""

    def __init__(self):
        self._entries = []  # list of (entry_dict, hash)

    def append(self, receipt):
        seq = len(self._entries)
        prev = self._entries[-1][1] if self._entries else CHAIN_GENESIS
        entry = {"seq": seq, "prev": prev, "receipt": receipt}
        self._entries.append((entry, entry_hash(entry)))
        return entry

    def head(self):
        """The checkpointable head: ``{"length", "hash"}`` (genesis hash for an empty log)."""
        return {
            "length": len(self._entries),
            "hash": self._entries[-1][1] if self._entries else CHAIN_GENESIS,
        }

    def entries(self):
        return [entry for entry, _ in self._entries]
