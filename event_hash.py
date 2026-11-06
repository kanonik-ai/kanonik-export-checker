# editorconfig-checker-disable-file
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Kanonik / eugene_gl
"""
event_hash.py — Python port of packages/events/event.go's hash chain.

Implements the canonical hash function for one event row, matching the
Go implementation in canonicalBytes() + Content.Hash() byte-for-byte.

each event's hash is SHA-256 over a length-prefixed
canonical byte sequence:

  tenant_id (16B)
  event_id (16B)
  event_type    (utf8, u32 length prefix)
  schema_version(utf8, u32 length prefix)
  entity_type   (optional-utf8: 0xFFFFFFFF=null OR u32 len + bytes)
  entity_id     (optional-uuid: 0xFFFFFFFF=null OR u32(16) + 16B)
  idempotency_key (16B)
  transaction_time (utf8 RFC3339Nano, u32 len prefix)
  valid_time      (utf8 RFC3339Nano, u32 len prefix)
  caller_subject  (utf8, u32 len prefix)
  caller_session  (optional-uuid)
  caller_tool     (optional-utf8)
  prev_hash       (32B, no length prefix)
  payload_bytes   (u32 len prefix + canonical-JSON bytes)

Used by chain/verify.py to recompute and compare against the
event_hash recorded on each event row, detecting tampering.

This file is part of the Auditor Export bundle (path:
chain/event_hash.py); auditor offline use requires stdlib only.
"""

from __future__ import annotations

import hashlib
import re
import struct
import uuid
from datetime import datetime, timezone
from typing import Any

from canonical_json import marshal as canonical_marshal

HASH_SIZE = 32
NULL_LENGTH_SENTINEL = 0xFFFFFFFF
MAX_FIELD_LEN = 0xFFFFFFFE
ZERO_UUID = uuid.UUID("00000000-0000-0000-0000-000000000000")
GENESIS_PREV_HASH = b"\x00" * HASH_SIZE


def _append_uuid(buf: bytearray, value: uuid.UUID) -> None:
    buf.extend(value.bytes)


def _append_optional_uuid(buf: bytearray, value: uuid.UUID) -> None:
    if value == ZERO_UUID:
        buf.extend(struct.pack(">I", NULL_LENGTH_SENTINEL))
        return
    # Present-marker = 16 (UUID length).
    buf.extend(struct.pack(">I", 16))
    buf.extend(value.bytes)


def _append_utf8(buf: bytearray, value: str) -> None:
    raw = value.encode("utf-8")
    if len(raw) > MAX_FIELD_LEN:
        raise ValueError(f"event_hash: utf8 field exceeds {MAX_FIELD_LEN} bytes")
    buf.extend(struct.pack(">I", len(raw)))
    buf.extend(raw)


def _append_optional_utf8(buf: bytearray, value: str) -> None:
    if value == "":
        buf.extend(struct.pack(">I", NULL_LENGTH_SENTINEL))
        return
    _append_utf8(buf, value)


def _append_bytes(buf: bytearray, data: bytes) -> None:
    if len(data) > MAX_FIELD_LEN:
        raise ValueError(f"event_hash: bytes field exceeds {MAX_FIELD_LEN} bytes")
    buf.extend(struct.pack(">I", len(data)))
    buf.extend(data)


def format_rfc3339_nano_utc(value: str) -> str:
    """Match Go's time.RFC3339Nano output for UTC times.

    Go writes nanosecond-precision times with a trailing 'Z' suffix and
    strips trailing zeros from the fractional seconds. Python emits
    microsecond precision by default with a '+00:00' suffix; we
    normalise to match Go.

    Input is the RFC3339-formatted timestamp string as carried in
    events.jsonl (Go serialised it via time.Time.MarshalJSON → RFC3339Nano).
    We round-trip via datetime to validate then re-emit.
    """
    # Accept Z or +00:00.
    normalised = value
    if normalised.endswith("Z"):
        normalised = normalised[:-1] + "+00:00"
    # Python's fromisoformat handles +00:00 cleanly but not arbitrary
    # offset; for our chain-hash use case all timestamps are UTC.
    dt = datetime.fromisoformat(normalised)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    # Build the string Go's RFC3339Nano would have produced — same
    # bytes Go fed into canonicalBytes() at signing time.
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    # Append fractional seconds from microseconds, stripping trailing
    # zeros (Go's RFC3339Nano behaviour). Note: Go can carry nanoseconds
    # but Postgres timestamptz truncates at microseconds and our
    # transaction_time is .Truncate(time.Microsecond), so re-emission
    # at microsecond resolution is byte-identical to the originally
    # signed string.
    micros = dt.microsecond
    if micros != 0:
        frac = f"{micros:06d}".rstrip("0")
        base += "." + frac
    base += "Z"
    return base


def _uuid_from_field(value: str | None) -> uuid.UUID:
    """Parse a UUID string (possibly empty) → uuid.UUID (Nil on empty)."""
    if not value:
        return ZERO_UUID
    return uuid.UUID(value)


def compute_event_hash(event: dict[str, Any]) -> bytes:
    """Recompute the SHA-256 chain hash for one event row.

    event must be one entry from events.jsonl as parsed (json.loads).
    Required fields: tenant_id, event_id, event_type, schema_version,
    idempotency_key, transaction_time, valid_time, caller_subject,
    prev_hash (base64), payload (base64 of canonical JSON).
    Optional: entity_type, entity_id, caller_session, caller_tool.

    Returns the 32-byte SHA-256 digest.
    """
    import base64 as b64
    buf = bytearray()
    _append_uuid(buf, uuid.UUID(event["tenant_id"]))
    _append_uuid(buf, uuid.UUID(event["event_id"]))
    _append_utf8(buf, event["event_type"])
    _append_utf8(buf, event["schema_version"])
    _append_optional_utf8(buf, event.get("entity_type", "") or "")
    _append_optional_uuid(buf, _uuid_from_field(event.get("entity_id")))
    _append_uuid(buf, uuid.UUID(event["idempotency_key"]))
    _append_utf8(buf, format_rfc3339_nano_utc(event["transaction_time"]))
    _append_utf8(buf, format_rfc3339_nano_utc(event["valid_time"]))
    _append_utf8(buf, event["caller_subject"])
    _append_optional_uuid(buf, _uuid_from_field(event.get("caller_session")))
    _append_optional_utf8(buf, event.get("caller_tool", "") or "")

    prev_hash = b64.b64decode(event["prev_hash"]) if event.get("prev_hash") else GENESIS_PREV_HASH
    if len(prev_hash) != HASH_SIZE:
        raise ValueError(
            f"event_hash: prev_hash must be {HASH_SIZE} bytes, got {len(prev_hash)}"
        )
    buf.extend(prev_hash)

    # Payload arrived in the JSONL as base64-encoded canonical JSON bytes.
    payload_b64 = event["payload"]
    payload_bytes = b64.b64decode(payload_b64) if payload_b64 else b""
    _append_bytes(buf, payload_bytes)

    return hashlib.sha256(bytes(buf)).digest()


# Canonical chain-root payload reconstruction. Mirrors
# packages/eventstore/signer/signer.go's ChainRootPayload.
#
# The chain root is signed over canonical-JSON of:
# {version, tenant_id, highest_seq, highest_hash, signed_at, signer_key_id}
# where highest_hash is base64 of head_event_hash and signed_at is the
# RFC3339Nano-formatted timestamp.
#
# VERSION SEMANTICS + BACK-COMPAT (the versioned-signature rules).
# The signed `highest_seq` slot's MEANING is version-dependent, but the
# reconstruction is value-agnostic: we sign/verify over the bytes as
# presented, never over a re-derived count. Concretely:
#
# * v2 (current): chain_root.json carries version="v2" and chain_length
# = the tenant's own event count. We reconstruct highest_seq from
# chain_length and version from the field -> byte-identical to what
# the Go signer produced.
# * v1 (legacy): already-exported auditor bundles carry NO version field
# (or "v1") and chain_length = the global head sequence_number. We
# default version to "v1" and still reconstruct highest_seq from
# chain_length -> byte-identical to what those bundles were signed
# over. They KEEP verifying.
#
# Crucially, nothing here asserts chain_length == the event count: the
# verifier verifies the SIGNATURE over the canonical payload as-presented.
# That single rule covers both old-global and new-tenant-count roots.

# Default chain-root version when chain_root.json carries no `version`
# field — i.e. a legacy bundle exported before Amendment 2. Such roots
# were signed with version "v1" (global head sequence in highest_seq).
DEFAULT_CHAIN_ROOT_VERSION = "v1"

# Regex to match Go time.RFC3339Nano with nanosecond precision (re-used
# by tests to round-trip-validate timestamps when needed).
RFC3339_NANO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


def build_chain_root_signed_payload(chain_root: dict[str, Any]) -> bytes:
    """Recompute the bytes the chain-root signer signed.

    chain_root is the parsed chain_root.json (per ChainRootEntry in
    packages/auditorexport/bundle.go). Returns the canonical-JSON
    serialisation of ChainRootPayload — the same bytes Go's
    eventstore.SignChainHead built before signing.
    """
    import base64 as b64
    head_hash = chain_root.get("head_event_hash") or chain_root.get("HeadEventHash")
    if isinstance(head_hash, str):
        # Already base64 (JSON []byte default).
        head_hash_b64 = head_hash
    elif isinstance(head_hash, (bytes, bytearray)):
        head_hash_b64 = b64.b64encode(head_hash).decode("ascii")
    else:
        raise ValueError("chain_root: head_event_hash missing or wrong type")

    signed_at = chain_root.get("signed_at") or chain_root.get("SignedAt")
    if not signed_at:
        raise ValueError("chain_root: signed_at missing")
    signing_key_id = chain_root.get("signing_key_id") or chain_root.get("SigningKeyID")
    if "chain_length" in chain_root:
        chain_length = chain_root.get("chain_length")
    else:
        chain_length = chain_root.get("ChainLength")
    tenant_id = chain_root.get("tenant_id") or chain_root.get("TenantID")

    # Read the signed version marker from the bundle. Legacy bundles carry
    # no `version` field -> default "v1" (global-sequence semantics), which
    # is exactly the version those bundles were signed with. New (v2)
    # bundles carry version="v2" (tenant-event-count semantics). Either way
    # we feed the value back verbatim so the reconstructed bytes match the
    # original signature. Per the versioned-signature rules.
    version = (
        chain_root.get("version")
        or chain_root.get("Version")
        or DEFAULT_CHAIN_ROOT_VERSION
    )

    payload = {
        "version": version,
        "tenant_id": tenant_id,
        "highest_seq": _strict_seq(chain_length),
        "highest_hash": head_hash_b64,
        "signed_at": _normalise_signed_at(signed_at),
        "signer_key_id": signing_key_id,
    }
    return canonical_marshal(payload)


def _strict_seq(v: Any) -> int:
    """A signed sequence number: a whole JSON integer or a string of ASCII digits, nothing else (not 41.9, not
    " 41", "+41", "41junk", or digits of another script). verify.mjs reads it the same way."""
    if isinstance(v, bool):
        raise ValueError("sequence number is a boolean")
    if isinstance(v, int):
        if abs(v) > 2**53 - 1:
            raise ValueError("sequence number is beyond 2^53-1")  # verify.mjs refuses it rather than round it
        return v
    if isinstance(v, float) and v.is_integer() and abs(v) <= 2**53 - 1:
        return int(v)  # JSON has one number type: 41.0 is 41, as verify.mjs reads it
    if isinstance(v, str) and re.fullmatch(r"[0-9]+", v, re.ASCII):
        n = int(v)
        if n > 2**53 - 1:
            raise ValueError("sequence number is beyond 2^53-1")
        return n
    raise ValueError("sequence number is not a whole number")


def build_record_checkpoint_signed_payload(checkpoint: dict[str, Any]) -> bytes:
    """Recompute the bytes the signer signed for a single-record checkpoint.

    A record checkpoint attests ONE event: the same key and the same canonical
    payload shape as a chain root, with version "record-v1", highest_seq the
    record's own sequence number and highest_hash its event hash. The chain is
    linear, so proving inclusion under a chain root would need every later
    event; the checkpoint attests the one record without them.
    """
    event_hash = checkpoint.get("event_hash")
    if not isinstance(event_hash, str) or not event_hash:
        raise ValueError("checkpoint: event_hash missing")
    signed_at = checkpoint.get("signed_at")
    if not signed_at:
        raise ValueError("checkpoint: signed_at missing")
    if "sequence_number" not in checkpoint:
        raise ValueError("checkpoint: sequence_number missing")
    payload = {
        "version": checkpoint.get("version") or RECORD_CHECKPOINT_VERSION,
        "tenant_id": checkpoint.get("tenant_id"),
        "highest_seq": _strict_seq(checkpoint["sequence_number"]),
        "highest_hash": event_hash,
        "signed_at": _normalise_signed_at(signed_at),
        "signer_key_id": checkpoint.get("signing_key_id"),
    }
    return canonical_marshal(payload)


RECORD_CHECKPOINT_VERSION = "record-v1"


def _normalise_signed_at(value: str) -> str:
    """Format signed_at the same way Go's time.Format(time.RFC3339Nano) did.

    Go's eventstore.SignChainHead does:
        signedAt = time.Now().UTC().Truncate(time.Microsecond)
        payload.SignedAt = signedAt.Format(time.RFC3339Nano)

    Then the JSON-serialised chain_root.SignedAt is re-marshalled
    independently as time.Time → MarshalJSON which uses RFC3339Nano too.
    Both forms strip trailing zeros from the fractional second.

    Our input is whatever the chain_root.json field carries; we re-emit
    in the byte-identical Go RFC3339Nano form so the signed-payload
    reconstruction matches what was signed.
    """
    return format_rfc3339_nano_utc(value)
