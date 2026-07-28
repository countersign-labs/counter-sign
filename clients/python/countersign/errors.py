# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""Error types — mirror src/core/errors.ts."""


class CountersignError(Exception):
    """Any counter-sign protocol violation (fail closed)."""


class InvalidCountersignatureError(CountersignError):
    """A receipt/resolution failed verification or an invariant check."""
