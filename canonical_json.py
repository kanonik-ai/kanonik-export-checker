# editorconfig-checker-disable-file
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Kanonik / eugene_gl
"""
canonical_json.py — Python port of packages/canonical-json/canonical.go.

Produces a deterministic byte form suitable for hashing, matching the
Go implementation byte-for-byte for every value Kanonik canonical-model
payloads emit (objects, arrays, strings, ints, floats, bools, null).

Rules (per the canonical-JSON rules):
  - Object keys sorted lexicographically (string compare, not numeric).
  - No insignificant whitespace.
  - Integers as their shortest decimal string; an integer outside int64 is
    refused unless it is how Go's JSON writes some float64 (then it is
    written as a float).
  - Floats via Go's strconv.FormatFloat 'g' precision -1; a whole-number
    float below 2^63 is written as an integer, as Go does for a stored
    (float64) number.
  - Strings: minimal JSON escapes (\\ " plus control chars).
  - Booleans + null: bare JSON forms.

This module is part of the Auditor Export bundle (path: chain/canonical_json.py)
so an auditor can verify hash-chain integrity offline without any
Kanonik install. Stdlib-only.
"""

from __future__ import annotations

import json
import math
from decimal import Decimal
from typing import Any


def marshal(value: Any) -> bytes:
    """Serialize value to canonical-JSON bytes.

    Mirrors canonicaljson.Marshal in Go (round-trip through stdlib then
    re-emit with canonical ordering).
    """
    # Round-trip through stdlib JSON so we accept anything stdlib does.
    raw = json.dumps(value, allow_nan=False, ensure_ascii=False)
    # parse_float=Decimal keeps the lexical form for the canonicalizer to
    # normalise the same way Go's strconv does.
    generic = json.loads(raw, parse_float=Decimal, parse_int=int)
    return _encode(generic)


def _encode(value: Any) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, bool):
        # Defensive (bool is subclass of int; check above).
        return b"true" if value else b"false"
    if isinstance(value, int):
        if not -(2**63) <= value < 2**63:
            # Same rule as Go: outside int64 only when it is how Go's json writes a
            # float64 (shortest digits, zero padded).
            try:
                f = float(value)
                exact = format(Decimal(repr(f)).normalize(), "f") == str(value)
            except (OverflowError, ValueError):
                exact = False
            if not exact:
                raise ValueError("canonical_json: integer outside int64 cannot be represented exactly")
            return _encode_number(float(value))
        return str(value).encode("ascii")
    if isinstance(value, (float, Decimal)):
        return _encode_number(value)
    if isinstance(value, list):
        parts = [b"["]
        for i, item in enumerate(value):
            if i > 0:
                parts.append(b",")
            parts.append(_encode(item))
        parts.append(b"]")
        return b"".join(parts)
    if isinstance(value, dict):
        # Sort keys lexicographically.
        keys = sorted(value.keys())
        parts = [b"{"]
        for i, key in enumerate(keys):
            if i > 0:
                parts.append(b",")
            parts.append(_encode_string(key))
            parts.append(b":")
            parts.append(_encode(value[key]))
        parts.append(b"}")
        return b"".join(parts)
    raise TypeError(f"canonical_json: unsupported type {type(value).__name__}")


# Mapping mirrors Go's encodeString in packages/canonical-json/canonical.go.
_ESCAPES = {
    ord('"'): b'\\"',
    ord("\\"): b"\\\\",
    ord("\b"): b"\\b",
    ord("\f"): b"\\f",
    ord("\n"): b"\\n",
    ord("\r"): b"\\r",
    ord("\t"): b"\\t",
}


def _encode_string(s: str) -> bytes:
    """Mirror Go's encodeString — UTF-8 bytes with minimal escapes."""
    out = bytearray(b'"')
    for ch in s.encode("utf-8"):
        if ch in _ESCAPES:
            out.extend(_ESCAPES[ch])
        elif ch < 0x20:
            out.extend(f"\\u{ch:04x}".encode("ascii"))
        else:
            out.append(ch)
    out.append(ord('"'))
    return bytes(out)


def _encode_number(value: Decimal | float) -> bytes:
    """Mirror Go's encodeNumber for a float64 value.

    A whole number below 2^63 is written as an integer. Otherwise Go writes strconv.FormatFloat(f, 'g', -1, 64): the shortest round-trip
    digits, in %e form when the decimal exponent is < -4 or >= 6 (shortest
    mode uses 6 as the precision for that test), else plain decimal. -0 -> 0.
    NaN/Inf are rejected.
    """
    if isinstance(value, Decimal) and not value.is_finite():
        raise ValueError("canonical_json: NaN/Inf cannot be represented")
    f = float(value)
    if math.isnan(f) or math.isinf(f):
        raise ValueError("canonical_json: NaN/Inf cannot be represented")
    if f == 0:
        return b"0"
    if f == int(f):
        # Go reads a stored number as float64 and json writes a whole one as its
        # shortest digits padded with zeros (487743590154645570, not ...568); a
        # value that fits int64 then goes out as that integer.
        whole = format(Decimal(repr(f)).normalize(), "f")
        if "." not in whole and -(2**63) <= int(whole) < 2**63:
            return whole.encode("ascii")
    sign, digits, exp = Decimal(repr(f)).as_tuple()
    ds = "".join(map(str, digits)).rstrip("0") or "0"
    dp = len(digits) + exp  # decimal point position relative to the digit string start
    # strip leading zeros of digit string (repr never yields them for f != 0 except 0.x)
    lead = len(ds) - len(ds.lstrip("0"))
    if lead:
        ds = ds[lead:]
        dp -= lead
    x = dp - 1
    neg = "-" if sign else ""
    if x < -4 or x >= 6:
        mant = ds[0] + ("." + ds[1:] if len(ds) > 1 else "")
        e = f"{'-' if x < 0 else '+'}{abs(x):02d}"
        return f"{neg}{mant}e{e}".encode("ascii")
    if dp <= 0:
        out = "0." + "0" * (-dp) + ds
    elif dp >= len(ds):
        out = ds + "0" * (dp - len(ds))
    else:
        out = ds[:dp] + "." + ds[dp:]
    return (neg + out).encode("ascii")
