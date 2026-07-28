# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
Canonical JSON — byte-identical to the counter-sign reference (src/core/canonical.ts).

Object keys are sorted lexicographically at every depth (by UTF-16 code unit, to
match JavaScript's String comparison), there is no insignificant whitespace, output
is UTF-8, ``None`` serializes as ``null``, and non-finite numbers are rejected. Both
this and the TypeScript implementation MUST produce identical bytes for equal values,
because these bytes are what get signed.
"""
import json
import math

_MAX_DEPTH = 64


def _utf16_order(key: str) -> bytes:
    # JavaScript's Array.prototype.sort compares strings by UTF-16 code unit;
    # utf-16-be bytes compare lexicographically in exactly that order.
    return key.encode("utf-16-be")


def canonicalize(value, _depth: int = 0) -> str:
    if _depth > _MAX_DEPTH:
        raise ValueError("cannot canonicalize: value nested too deeply")
    if value is None:
        return "null"
    # bool is a subclass of int — must be checked first.
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("cannot canonicalize non-finite number")
        # Match JS Number->string: an integral float renders without a fraction.
        return str(int(value)) if value.is_integer() else repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v, _depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=_utf16_order)
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + canonicalize(value[k], _depth + 1)
                for k in keys
            )
            + "}"
        )
    raise TypeError(f"cannot canonicalize value of type {type(value).__name__}")
