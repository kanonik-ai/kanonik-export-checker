#!/usr/bin/env python3
# editorconfig-checker-disable-file
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Kanonik / eugene_gl
"""
verify.py - Standalone offline verifier for Kanonik Auditor Export bundles.

Usage:
    python3 verify.py <bundle-dir-or-tar.gz>

Exit codes:
    0  - every check PASSed
    1  - at least one check FAILed (chain tampered, missing artifacts,
         signature broken, SoD breached, etc.), or the result is DEGRADED
         (DEGRADED means no check failed but at least one could not be assessed)
    2  - usage error or unreadable bundle

Output:
    - JSON report on stdout (one object per check + a summary).
    - Human-readable line per check on stderr.

Bundle mode runs eleven checks, in this order (chain/README.md, "What it
checks", explains each one):
    1. hash_chain_integrity   - every event's prev_hash matches the
                                prior event's event_hash; recompute every
                                event_hash and confirm it matches.
    2. chain_completeness     - sequence numbers are unique and (v2 chain
                                roots) the signed event count matches.
    3. chain_root_signature   - verify the chain root's ECDSA P-384 /
                                SHA-384 signature against a PINNED Kanonik
                                key (built into this file; trusted_keys.json is its copy). The bundle's own
                                public_key.pem is a last-resort fallback
                                only, reported DEGRADED, never PASS.
    4. verifier_verdict_presence - every *.committed.v1 event carries a
                                non-rejected Verifier verdict, either
                                EMBEDDED in the event (mapping, audit
                                finding) or as a standalone
                                verifier.verdict.v1 referencing it.
    5. sod_separation_of_duties - proposer != approver for every
                                approval pair, unless the chain discloses
                                why one person could do both.
    6. two_act_oversight       - when a governance record one person
                                accepted is sealed, the sealer differs;
                                records awaiting the second act are
                                counted, not failed.
    7. member_attestation      - approval members under the recorded-click
                                regime carry an attestation.
    8. skill_provenance       - every skill activation event carries
                                {manifest_hash, signing_identity,
                                signing_key_id}; flag the build-time-
                                YAML-loader fallback as degraded.
    9. reproducibility_tuple_completeness - every verifier.verdict.v1
                                carries the reproducibility fields.
   10. prompt_integrity        - every LLM-tier verifier.verdict.v1's
                                prompt_hash matches a released Kanonik
                                Verifier prompt (chain/verifier_prompt_
                                registry.json; hashes only, no prompt text).
                                An unrecognised prompt_hash is a fabricated /
                                tampered prompt and FAILs.
   11. file_checksums          - every file matches its SHA-256 in
                                MANIFEST.json.

Air-gap by default: no network calls unless --online is passed.

This script is shipped INSIDE every Auditor Export bundle so an
auditor verifies it WITHOUT installing Kanonik. The script + its two
companion modules (canonical_json.py, event_hash.py) are stdlib-only
except for the chain-root signature check (which uses `cryptography`,
declared in requirements.txt).

If `cryptography` is unavailable, the chain_root_signature check is
reported as DEGRADED (not FAIL) so the rest of the bundle's claims
can still be independently verified. The auditor is told plainly that
the signature could not be cryptographically checked in this run.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import functools
import hashlib
import json
import os
import re
import sys
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Optional

# Allow the script to be invoked from the bundle root OR via `python3
# chain/verify.py`; either way, our companion modules sit next to us.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# Imported with explicit sys.path tweak above so the verifier works
# regardless of cwd (an auditor running `python3 chain/verify.py .`).
import event_hash as event_hash_mod  # noqa: E402
from canonical_json import marshal as canonical_marshal  # noqa: E402
from event_hash import (  # noqa: E402
    build_record_checkpoint_signed_payload,
    compute_event_hash,
    build_chain_root_signed_payload,
    DEFAULT_CHAIN_ROOT_VERSION,
)


# VERIFIER_VERSION is this offline verifier's own version, distinct from the
# bundle schema_version. Version 2.0.0 recognises the record-kind self-seal: one
# person accepting AND sealing a routine record (evidence, a control test, a
# mapping) that the tenant's author-may-self-seal policy permits without a
# second reviewer, disclosed with no separate exception event. An export that
# contains such a self-seal requires verifier version 2.0.0 or later; an older
# 1.x copy reports those approvals as self_approval failures because it predates
# the rule.
#
# Version 2.1.0 adds the two-act oversight check: a governance record the author
# only ACCEPTED (parked for a second person) must be sealed later by a DIFFERENT
# subject before it commits. A record kind the author sealed with one click
# needs no second person and is never asked to show one. This check is additive
# and never changes the verdict of any check that shipped in 2.0.0: an export
# with a two-act trail still PASSES on a 2.0.0 copy (which simply does not run
# the two-act check), and the extra oversight verdict is available from 2.1.0
# on. Every export produced before the record-kind self-seal, and every
# governance-kind or sole-admin case, still verifies unchanged on the verifier
# it originally shipped with. The bundle README and verify.html state the
# minimum verifier version for the export.
#
# Version 2.2.0 adds the per-member attestation check: an approval produced under
# the recorded-click regime carries attestation_required=true, and every member of
# such an approval must then carry a non-empty attestation (a person and their
# recorded words) for that item. The requirement is gated on the approval's own
# attestation_required flag, which lives in the hashed payload, so it cannot be
# stripped to dodge the check without breaking the chain. It is additive: an export
# whose approvals predate the recorded click (no attestation_required, the flag
# absent) is not asked for attestations and still verifies, on this verifier and on
# 2.1.0. The bundle README and verify.html state the minimum verifier version for
# the export.
# 2.3.0 (2026-09-09): two record kinds join the author-may-self-seal default
# (claim, questionnaire_response) and claim.committed.v1 carries its
# groundedness verdict embedded. Without this bump every self-sealed saved
# answer or answer set would FAIL the customer's own check on 2.2.0.
# 2.4.0 (2026-09-10): single-record mode. `verify.py --record proof.json` checks
# one sealed record a company handed you: the event hash recomputed from the
# record's own bytes, the signed record checkpoint over that hash, the verdict
# tuple, the human approval, whether a newer version existed at export time,
# and that this verifier is new enough for the file. A bundle verifies exactly
# as on 2.3.0; nothing in the bundle path changed.
# 2.5.0 (2026-09-10): three record kinds join the author-may-self-seal default
# and the rule-tier-only set (obligation, lens_decision, lens_applicability:
# who is asking, and the lens chosen to answer them). Without this bump every
# self-sealed obligation or lens decision would FAIL the customer's own check
# on 2.4.0. Nothing else in either path changed.
# 2.6.0 (2026-09-10): the migration summary joins the author-may-self-seal
# default and the rule-tier-only set (migration_summary: the bounded population
# of a legacy tool's export carried into the record). Nothing else in either
# path changed.
# 2.7.0 (2026-09-19): risk and remediation join the author-may-self-seal
# default. A risk entry and a corrective action need an
# owner, not a second signature; risk_acceptance and exception stay
# second-person. Without this bump a risk or remediation its author sealed
# alone would FAIL the customer's own check on 2.6.0. The rule-tier-only set is
# unchanged. Nothing else in either path changed.
# 2.7.1 (2026-09-25): a NOT_ASSESSED verdict (the Verifier declined to judge an
# entity that made no claim) with a recorded human approver lets the write
# stand, like HUMAN_REVIEW: it seals on the ordinary click with no override.
# Without this an ordinary approval of a not-assessed control FAILED the
# customer's own check. Without an approver it still fails closed. Nothing
# else in either path changed. 2.8.0 is reserved for the checks of the next
# pack format (v2): a v2 pack stamps min_verifier_version 2.8.0, so this toolkit
# must refuse it rather than pass a pack it cannot check (check_file_checksums
# refuses any minimum above MAX_SUPPORTED_BUNDLE_REQUIREMENT, Amendment 9).
# 2.7.2 (2026-09-28): operational_fact.committed.v1 is classified as
# a committed kind whose soundness verdict is embedded and required. Without it
# 2.7.1 FAILs every sealed operational fact as committed_kind_unclassified. The
# fact is second-person (never in the author-may-self-seal default), so the
# SoD check is unchanged. Nothing else in either path changed.
# 2.7.3 (2026-10-01): skill provenance is a verifiable signature, not a recorded
# identity string. A skill activation now carries the bundle's signature, which
# this toolkit verifies against the pinned first-party skill-signing key
# (the built-in key list, skill_signing_keys); a bad signature FAILs and an
# activation without one is DEGRADED. No other check changed.
# 2.7.4 (2026-10-01): every gated write is classified, not only *.committed.v1.
# Six human-decision writes (evidence.captured, control_test.executed,
# risk.accepted, remediation.applied, exception.approved, conformance.attested)
# are verdict-exempt by design and are now counted in the report; the audit
# session (audit.session.created) joins the historical-optional kinds (an
# embedded or paired verdict is checked, an absent one DEGRADES, a rejected one
# FAILs); any other event that carries an approval token and an
# approver and is in no known set FAILs (gated_write_unclassified). Nothing
# else in either path changed; a bundle that checked clean on 2.7.2 and holds
# only known kinds keeps its verdict, except one carrying an audit session with
# a rejected verdict and no approver, which now FAILs, or one with no verdict at
# all, which now DEGRADES.
# 2.7.4 (2026-10-01): the verifier stops taking the audited party's word. A
# REJECTED verdict stands only with a separate approval.override.recorded.v1 on
# the chain (matched by committed event id, same approver, a reason); the inline
# override_acknowledged flag is ignored. The sole-admin SoD exception is accepted
# only if the active-admin set, recomputed from the chain's role events as of the
# approval, is exactly the approver; a bundle with no role events reports
# DEGRADED. The headline reports author-sealed vs dual-controlled counts instead
# of "approval evidence complete". Nothing else in either path changed.
# 2.7.4 (2026-10-01): a bundle may WITHHOLD events outside the reader's grant
# (the customer's commercial relationship with Kanonik: billing, invoices,
# seat charges, discount and comp codes). A withheld entry keeps its position
# and its event_hash (the leaf) and carries no content; the hash-chain check
# accepts the stored hash for it, still checks every link around it, and
# refuses a withheld marker on an entry that carries content or any identity.
# The positions are reported in their own check: DEGRADED unless a signed
# withheld_positions.json (2.7.8) accounts for each one, then PASS. A 2.7.3 or older copy
# fails such a bundle on the hash check, never passes it.
# 2.7.5 (2026-10-04): the text a person reads says Passed / Passed with notes /
# Failed (the JSON keeps PASS / DEGRADED / FAIL exactly), and prints the checker
# version and the package code (first 12 hex of the signed chain head, 4-4-4).
# Self-approval notes count distinct approval ids, not events; the SoD
# summary counts approval.member.rejected.v1 as a rejection of its approval id
#, count only. No check's verdict changed. (2.8.0 stays reserved for the
# v2 pack checks, so this is a patch step.)
# 2.7.6 (2026-10-04): a bundle signed by the Kanonik public sample key (trusted
# key class "sample") verifies as Passed with notes, never Passed: the
# signature check is DEGRADED with a note naming the sample key. No other
# check changed. (2.8.0 stays reserved for the v2 pack checks.)
SAMPLE_KEY_NOTE = "signed with the Kanonik public sample key: synthetic data, not a customer record"
# 2.7.7 (2026-10-04): verdict stance per lifecycle gated write.
# Replacement findings and revised applicability decisions need
# their own embedded verdict; recorded obligations, lens decisions and migration
# summaries need a passing rule verdict for that record; supersession pointers,
# staleness markers and session transitions are reported as exempt; the six
# human-decision kinds must name the approver. (2.8.0 stays reserved for the
# v2 pack checks.)
# 2.7.8 (2026-10-04): a bundle that withholds commercial events carries a
# separately signed withheld_positions.json. The same pinned key must sign the
# chain root and the exact list of withheld positions (sequence, hash, domain);
# a valid statement makes the withheld-positions check PASS with the count, a
# changed list or foreign key FAILs, and without a statement it stays DEGRADED.
# (2.8.0 stays reserved for the v2 pack checks.)
# 2.7.10 (2026-10-06): wording only. The trust headline no longer claims
# that no trust is needed; it names what is still relied on (pinned
# signing keys, withheld-entries list, prompt registry). The browser page says
# the seal is signed by a key in the pinned set, not "the key in this bundle".
# 2.7.9 (2026-10-04, Amendment 9): README.txt and records.csv in new bundles;
# the generic checksum check supports these files without requiring them in old
# packs. (2.8.0 stays reserved for the v2 pack checks.)
# 2.7.11 (2026-10-10): a finalised audit-session pack (a non-contiguous selection of
# the workspace chain) verifies per event: each hash recomputes and a signed record
# checkpoint in session_checkpoints.json attests it. Gaps are stated, not failed;
# an edited, reordered or unattested event, or a checkpoint whose event is
# missing, FAILs. An event removed together with its own checkpoint is not
# detectable (nothing signs the event list). A pack with
# no session_checkpoints.json is checked as before.
# 2.7.12 (2026-10-15, founder ruling M-152): a policy commit's own in-record Verifier
# verdict is accepted (a missing, malformed or rejected one, or one contradicted by
# a standalone rejection, still FAILs); a recorded-click approval member whose write
# was refused (canonical.write.failed.v1 for that approval_jti and proposal_id) is
# skipped in member_attestation. Every other check is unchanged.
# 2.7.13 (2026-10-17, founder ruling M-169, Q57): reads the new package layout as well as the old
#: the machine part under Verification/, MANIFEST.json listing every file of the
# package by its path from the package folder. No check changed; only where the files are looked for.
# 2.7.14 (2026-10-21): the seal covers the files. A package from this version on carries
# Verification/package_seal.json: the chain-root key's signature over the SHA-256 of MANIFEST.json and
# over the SHA-256 of every file the package lists. file_checksums now fails a file edited together with
# its listed checksum, a changed MANIFEST.json, a file added or dropped, and a seal not signed by a
# pinned key, and names the file. A package with no seal (an older export) reads Passed with notes,
# never Passed: its file list is unsigned. No other check changed.
# 2.7.15 (2026-10-21): a package that was sealed cannot be unsealed. Chain roots signed from this version
# on carry payload version "v3" (same fields as "v2"), which means: this package must carry a package seal.
# file_checksums FAILS a package whose signed root says "v3" (or whose root was signed by a pinned key from the
# date that key requires seals) but whose package_seal.json is missing, instead of reading it as an older
# package. chain_root_signature FAILS a root with an empty signature and a root version it does not know.
# Packages made before this version (v1/v2 roots) read as before.
# 2.7.16 (2026-10-22): a withdrawn link (link.retracted.v1) is classified as a human decision that takes
# no model grade (lifecycle stance exempt). An older checker reads a package with a withdrawal as an unclassified
# gated write. No other check changed.
# 2.7.17 (2026-10-22): the trust page kinds (the trust page). Five kinds join the author-may-self-seal default (sod catalogue
# version 2: disclosure, access_grant, branding, nda_text, third_party_document; page_disclosure stays second-person),
# and the seven trust page writes are classified as human-decision writes. Without this bump a release its sharer
# approved alone, or any trust page write, would FAIL the customer's own check on 2.7.15. Nothing else changed.
# 2.7.18 (2026-10-22): a person's acknowledgement of the company's own policy (policy_acknowledgement) is a
# record kind the author may seal alone and a rule-tier-only record: its sealed event is classified as a
# deterministic record instead of an unclassified gated write. No other check changed.
# 2.7.19 (2026-10-24): `--disclosure` reads a signed kanonik-disclosure/v1 file (TB-26). Outcomes VERIFIED,
# VERIFIED_NON_PRODUCTION, UNKNOWN_ISSUER (the key id is not pinned), BAD_SIGNATURE (pinned id, signature does not
# verify), KEY_REVOKED, UNKNOWN_SCHEMA (refused by name), VERIFIER_TOO_OLD, MALFORMED; the status of the item is
# read only with --online and an unreadable status is "unknown", integrity as shown. The key file is version 2:
# every key has a status (active, retired, revoked), a revoked key's signatures fail in every mode, and an online
# key file is used only when a pinned production key signed it (continuity), otherwise it can add non-production
# keys only. 2.8.0 stays reserved for the v2 pack checks.
# 2.7.20 (2026-11-02): `--feed` reads a signed kanonik-trust-feed/v1 file: the `--disclosure` outcome words
# plus STALE (good signature, this checker's clock is past valid_until), the copy's age and each item's check code and
# status words as the copy states them, a file over 1 MiB refused before parsing, `--online` (live feed only from
# https://share.kanonik.ai/t/{slug}/feed.json, differences listed by item) and `--feed F --disclosure D` (is the item's
# signed manifest digest listed in the feed). No other check changed; `--disclosure` still needs only 2.7.19.
# 2.7.21 (2026-11-10): words only, and a new version because the published checker files' bytes changed (founder M-309 item 7).
# The notes under "verifier_verdict_presence" name a record kind in words ("obligation recorded") and give a plain reason
# instead of "obligation.recorded.v1: rule - gateway anchors the rule verdict against the canonical id"; the text output
# says once that the JSON's DEGRADED is "Passed with notes" and prints a signature that verified with notes, or could not
# be checked here, as "not fully (read the notes below)"; verify.html also words the cards of chain_completeness,
# two_act_oversight and member_attestation to match what each check proves. No check, no JSON field and no outcome changed.
# 2.7.22 (2026-11-12): a record the AI re-proposed after the safety check's refinement loop is paired to its standalone
# verdict by the graded content its sealed commit_provenance records (inputs hash, prompt, model, rule pack, lineage and
# the earlier proposed draft), for the control, procedure and policy kinds, when no id pairs it. A chain sealed
# that way read FAILED on 2.7.21 (committed_without_verdict). A rejected verdict is never hidden by an approved one, and
# nothing else loosened.
VERIFIER_VERSION = "2.7.22"
# A packaging-only bump must not claim the unimplemented Amendment 7 checks.
MAX_SUPPORTED_BUNDLE_REQUIREMENT = "2.7.4"


# ---------------------------------------------------------------------------
# Check-result model
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """One verification check's outcome.

    status is one of PASS, FAIL, DEGRADED. DEGRADED means the check
    could not be fully executed (e.g. cryptography lib absent) but
    no FAIL signal was found; auditor judgement required.
    """

    check: str
    status: str
    count: int = 0
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Structured numbers a check wants to hand to the headline (empty for most
    # checks, and then left out of the JSON output).
    details: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Bundle loading
# ---------------------------------------------------------------------------


def load_bundle(path: Path) -> Path:
    """Return a path to an extracted bundle root.

    Accepts either a directory (already extracted) or a .tar.gz file.
    For tar.gz, extracts to a tempdir; caller's responsibility to keep
    the script process alive while reading.
    """
    if path.is_dir():
        return path
    if not path.is_file():
        raise FileNotFoundError(f"bundle path not found: {path}")
    tmp = Path(tempfile.mkdtemp(prefix="kanonik-verify-"))
    with tarfile.open(path, "r:gz") as tf:
        # Safety: refuse path traversal entries (../).
        for member in tf.getmembers():
            if member.name.startswith("/") or ".." in Path(member.name).parts:
                raise ValueError(
                    f"bundle contains unsafe path: {member.name}"
                )
        # Python 3.12+ supports the `filter='data'` argument that does
        # the same path-safety check natively; try it for defence-in-depth.
        try:
            tf.extractall(tmp, filter="data")  # type: ignore[call-arg]
        except TypeError:
            tf.extractall(tmp)  # pragma: no cover  # noqa: S202
    return tmp


def resolve_layout(path: Path) -> tuple[Path, Path]:
    """Return (package_root, machine_dir) for an extracted package.

    Old layout: MANIFEST.json, events.jsonl and the rest of the machine part sit at the
    root, so both are the root. New layout: the package folder
    holds README, the report, Records/ and Tables/ and puts the machine part under
    Verification/. MANIFEST.json lists every file of the package by its path from the
    package folder, so the checksums are read from the package root while the chain,
    the root signature and the registries are read from Verification/. A package
    unpacked into one folder (a .tar.gz of the new layout) and a path given as
    Verification/ itself are both found.
    """
    path = path.resolve()  # "." has no name: Verification/ itself may be given as the current folder
    nested = (path / "Verification" / "MANIFEST.json").is_file()
    flat = (path / "MANIFEST.json").is_file()
    if nested and flat:
        # Two manifests: one could list fewer files than the other. Never pick one silently.
        raise ValueError("ambiguous package: MANIFEST.json at the root and in Verification/")
    if nested:
        # A manifest under Verification/ makes a new-layout package only when it lists files under Verification/. A flat
        # package that happens to be unpacked into a folder of that name lists them at its root: that is the old layout.
        if _manifest_lists_verification(path / "Verification" / "MANIFEST.json"):
            return path, path / "Verification"
        return path / "Verification", path / "Verification"
    if flat:
        # Given Verification/ itself: it is the machine part of a new-layout package only when its manifest lists files
        # under Verification/, and then the package folder above it must not carry a manifest of its own.
        if path.name == "Verification" and (path.parent / "MANIFEST.json").is_file():
            # Whatever this manifest lists, the folder above has one too: never choose between them.
            raise ValueError("ambiguous package: MANIFEST.json at the root and in Verification/")
        if path.name == "Verification" and _manifest_lists_verification(path / "MANIFEST.json"):
            return path.parent, path
        return path, path
    if path.is_dir():
        subs = [d for d in path.iterdir() if d.is_dir()]
        if len(subs) == 1 and (
            (subs[0] / "Verification" / "MANIFEST.json").is_file() or (subs[0] / "MANIFEST.json").is_file()
        ):
            return resolve_layout(subs[0])
    return path, path


def _manifest_lists_verification(manifest_path: Path) -> bool:
    try:
        doc = json.loads(manifest_path.read_text(encoding="utf-8"))
        sums = doc.get("file_checksums") if isinstance(doc, dict) else None
        return isinstance(sums, dict) and any(str(k).startswith("Verification/") for k in sums)
    except (OSError, ValueError):
        return False


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def _read_json(path: Path) -> Optional[dict[str, Any]]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Check 1 - hash-chain integrity
# ---------------------------------------------------------------------------


WITHHELD_EVENT_TYPE = "withheld.v1"
WITHHELD_DOMAINS = ("commercial",)


def is_withheld_entry(ev: dict[str, Any]) -> Optional[str]:
    """Classify an events.jsonl entry as served whole or withheld.

    Returns None for an entry served whole (no "withheld" marker). For a
    withheld entry returns "" when it has exactly the withheld shape (a known
    domain, the withheld.v1 type, no payload, a 32-byte event_hash) and a
    message when it does not. Marking an event that still carries content as
    withheld would skip its hash check, so that shape is refused.
    """
    marker = ev.get("withheld")
    if not marker:
        return None
    if marker not in WITHHELD_DOMAINS:
        return f"unknown withheld domain {marker!r}"
    if ev.get("event_type") != WITHHELD_EVENT_TYPE:
        return "a withheld entry must carry the withheld.v1 type"
    # Strictly empty, spelled the same way in verify.mjs: absent, null or "".
    # A payload of {} or [] is content-shaped, so it is refused.
    if ev.get("payload") not in (None, ""):
        return "a withheld entry must carry no payload"
    for field_name in (
        "schema_version", "entity_type", "entity_id", "idempotency_key",
        "caller_subject", "caller_session", "caller_tool",
    ):
        if ev.get(field_name) not in (None, ""):
            return f"a withheld entry must carry no {field_name}"
    try:
        if len(base64.b64decode(ev.get("event_hash") or "", validate=True)) != 32:
            return "a withheld entry must keep a 32-byte event_hash"
    except Exception:  # noqa: BLE001
        return "a withheld entry must keep a 32-byte event_hash"
    return ""


def _unsigned_withheld_positions(events: list[dict[str, Any]]) -> Optional[CheckResult]:
    """Report the positions this bundle withholds, or None when there are none.

    A withheld position keeps its place and its event_hash, so the chain, its
    links and the chain-root signature still verify. Its CONTENT cannot be
    checked, and nothing in the bundle proves WHICH positions Kanonik chose to
    withhold: a later holder could dress a failing event as withheld. So the
    report is DEGRADED, never PASS: the auditor sees exactly how many positions
    this verifier could not examine (2.7.4).
    """
    withheld = [e for e in events if e.get("withheld")]
    if not withheld:
        return None
    result = CheckResult(check="withheld_positions", status="DEGRADED", count=len(withheld))
    domains = sorted({str(e.get("withheld")) for e in withheld})
    result.notes.append(
        f"{len(withheld)} of {len(events)} positions are withheld "
        f"({', '.join(domains)}): their hashes and the links around them verify, "
        "but their content is outside this reader's grant and was not examined"
    )
    result.notes.append(
        "the bundle does not yet carry a signed statement of which positions "
        "may be withheld; confirm the withheld count with the company"
    )
    return result


def check_withheld_positions(
    events: list[dict[str, Any]],
    statement_bytes: Optional[bytes] = None,
    chain_root: Optional[dict[str, Any]] = None,
    trusted_keys: Optional[list[dict[str, Any]]] = None,
) -> Optional[CheckResult]:
    """Authenticate the exact withheld set with the root's pinned signing key.

    Missing statements retain the legacy verdict. A present but invalid
    statement fails, even if no events are marked withheld. The signature
    covers canonical bytes in a separate signing domain.
    """
    if statement_bytes is None:
        return _unsigned_withheld_positions(events)
    withheld = [e for e in events if e.get("withheld")]
    result = CheckResult(check="withheld_positions", status="PASS", count=len(withheld))
    try:
        statement = json.loads(statement_bytes)
        if not isinstance(statement, dict) or set(statement) != {"payload", "signature"}:
            raise ValueError("expected a payload and signature envelope")
        payload_bytes = base64.b64decode(statement["payload"], validate=True)
        signature = base64.b64decode(statement["signature"], validate=True)
        payload = json.loads(payload_bytes)
        if not isinstance(payload, dict) or set(payload) != {
            "version", "tenant_id", "chain_root_sha256", "signing_key_id", "positions"
        } or canonical_marshal(payload) != payload_bytes:
            raise ValueError("statement payload must use the canonical schema")
        if payload["version"] != "kanonik.withheld-positions.v1":
            raise ValueError("unknown withheld statement signing domain")
        if not chain_root or not chain_root.get("signature"):
            raise ValueError("statement requires a signed chain root")
        root_bytes = build_chain_root_signed_payload(chain_root)
        if payload["chain_root_sha256"] != hashlib.sha256(root_bytes).hexdigest():
            raise ValueError("statement belongs to a different chain root")
        if payload["tenant_id"] != chain_root.get("tenant_id") or payload["signing_key_id"] != chain_root.get("signing_key_id"):
            raise ValueError("statement tenant or key differs from the chain root")
        if any(e.get("tenant_id") != payload["tenant_id"] for e in events):
            raise ValueError("event belongs to a different tenant")
        positions = payload["positions"]
        if not isinstance(positions, list) or not positions or len(positions) != len(withheld):
            raise ValueError("statement must name exactly the withheld positions")
        expected = {}
        for e in withheld:
            state, seq = _canonical_int(e.get("sequence_number"))
            if state != "ok" or int(seq) <= 0 or seq in expected or is_withheld_entry(e) != "":
                raise ValueError("malformed or duplicate withheld event")
            expected[seq] = e
        previous = 0
        for position in positions:
            if not isinstance(position, dict) or set(position) != {"sequence_number", "event_hash", "domain"}:
                raise ValueError("malformed withheld position")
            seq = position["sequence_number"]
            if not isinstance(seq, str) or not re.fullmatch(r"[1-9][0-9]*", seq) or int(seq) <= previous:
                raise ValueError("positions must be unique and sorted positive decimal strings")
            previous = int(seq)
            e = expected.get(seq)
            if not e or position["domain"] != "commercial" or position["event_hash"] != e.get("event_hash"):
                raise ValueError("statement does not match a withheld position")
        # The same pinned public key must verify BOTH signatures. Matching
        # key-id labels alone is insufficient (environments can share labels).
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        matched = _verify_sig_against_trusted(signature, payload_bytes, trusted_keys or [])
        if matched is None:
            raise ValueError("withheld statement is not signed by a pinned key")
        pem = matched["pem"]
        pub = load_pem_public_key(pem.encode() if isinstance(pem, str) else pem)
        if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP384R1):
            raise ValueError("withheld statement requires an ECDSA P-384 key")
        pub.verify(base64.b64decode(chain_root["signature"], validate=True), root_bytes, ec.ECDSA(hashes.SHA384()))
        result.notes.append(
            f"{len(withheld)} commercial positions are signed as withheld by the chain-root key; "
            "their content is outside this reader's grant and was not examined"
        )
    except ImportError:
        result.status = "DEGRADED"
        result.notes.append("cryptography library not installed; cannot authenticate withheld positions")
    except Exception as exc:  # noqa: BLE001 - untrusted bundle, fail closed
        result.status = "FAIL"
        result.anomalies.append({"kind": "withheld_statement_invalid", "message": str(exc) or "withheld statement signature is invalid"})
    return result


def check_hash_chain(
    events: list[dict[str, Any]],
    session_doc: Optional[dict[str, Any]] = None,
    trusted_keys: Optional[list[dict[str, Any]]] = None,
    chain_root: Optional[dict[str, Any]] = None,
    manifest: Optional[dict[str, Any]] = None,
) -> CheckResult:
    """Walk events.jsonl in sequence-number order; recompute every
    event_hash; assert it matches the stored event_hash AND that
    prev_hash matches the prior event's event_hash.
    """
    if session_checkpoints_present(session_doc):
        # An audit-session pack is a selection, not a contiguous run: it is
        # checked per event against signed checkpoints instead.
        return check_session_pack_integrity(events, session_doc, trusted_keys, chain_root, manifest)
    result = CheckResult(check="hash_chain_integrity", status="PASS")
    if not events:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "empty_events",
            "message": "events.jsonl carries no events; nothing to verify",
        })
        return result

    sorted_events = sorted(events, key=lambda e: int(e.get("sequence_number", 0)))
    result.count = len(sorted_events)

    prior_hash_b64: Optional[str] = None
    withheld_count = 0
    for idx, ev in enumerate(sorted_events):
        seq = ev.get("sequence_number")
        stored_b64 = ev.get("event_hash") or ""
        withheld = is_withheld_entry(ev)
        if withheld is not None:
            # A withheld entry (2.7.4): the domain is outside the reader's
            # grant, so its content is absent and the stored event_hash is the
            # leaf. It is accepted only in the exact withheld shape, and its
            # prev_hash / the next event's prev_hash still bind it in place.
            if withheld:
                result.status = "FAIL"
                result.anomalies.append({
                    "kind": "withheld_entry_malformed",
                    "sequence_number": seq,
                    "event_id": ev.get("event_id"),
                    "message": withheld,
                })
            else:
                withheld_count += 1
            computed_b64 = stored_b64
        else:
            try:
                computed = compute_event_hash(ev)
            except Exception as e:  # noqa: BLE001
                result.status = "FAIL"
                result.anomalies.append({
                    "kind": "hash_compute_error",
                    "sequence_number": seq,
                    "event_id": ev.get("event_id"),
                    "message": f"could not recompute hash: {e}",
                })
                continue
            computed_b64 = base64.b64encode(computed).decode("ascii")

        if computed_b64 != stored_b64:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "event_hash_mismatch",
                "sequence_number": seq,
                "event_id": ev.get("event_id"),
                "stored_hash_b64": stored_b64,
                "computed_hash_b64": computed_b64,
                "message": (
                    "event_hash does not match recomputation; "
                    "event payload, header field, or hash was modified"
                ),
            })

        # Chain link check: this event's prev_hash must equal the
        # prior event's event_hash. The first event must reference
        # GENESIS_PREV_HASH (32 zero bytes).
        stored_prev_b64 = ev.get("prev_hash") or ""
        if idx == 0:
            expected_prev_b64 = base64.b64encode(b"\x00" * 32).decode("ascii")
            if stored_prev_b64 != expected_prev_b64:
                result.status = "FAIL"
                result.anomalies.append({
                    "kind": "genesis_prev_hash_mismatch",
                    "sequence_number": seq,
                    "event_id": ev.get("event_id"),
                    "message": (
                        "first event's prev_hash is not the genesis "
                        "sentinel (32 zero bytes); chain start tampered "
                        "or events.jsonl is missing leading events"
                    ),
                })
        else:
            assert prior_hash_b64 is not None
            if stored_prev_b64 != prior_hash_b64:
                result.status = "FAIL"
                result.anomalies.append({
                    "kind": "chain_link_broken",
                    "sequence_number": seq,
                    "event_id": ev.get("event_id"),
                    "expected_prev_hash_b64": prior_hash_b64,
                    "stored_prev_hash_b64": stored_prev_b64,
                    "message": (
                        "this event's prev_hash does not match the "
                        "prior event's event_hash; an event was "
                        "inserted, removed, or reordered"
                    ),
                })

        prior_hash_b64 = stored_b64

    if withheld_count:
        result.notes.append(
            f"{withheld_count} events are withheld (outside the reader's "
            "grant): their stored hashes are accepted as leaves and every "
            "chain link around them is checked"
        )
    if result.status == "PASS":
        result.notes.append(
            f"verified {len(sorted_events)} events; all hashes + chain "
            "links match"
        )
    return result


# ---------------------------------------------------------------------------
# Check 1 (audit-session pack form)
# ---------------------------------------------------------------------------

SESSION_CHECKPOINTS_FILE = "session_checkpoints.json"
SESSION_CHECKPOINTS_VERSION = "session-checkpoints.v1"


def session_checkpoints_present(doc: Any) -> bool:
    # Present means the file exists, whatever it holds: a malformed file is a
    # FAIL, never a quiet return to the contiguous walk.
    return doc is not None


def check_session_pack_integrity(
    events: list[dict[str, Any]],
    doc: Any,
    trusted_keys: Optional[list[dict[str, Any]]] = None,
    chain_root: Optional[dict[str, Any]] = None,
    manifest: Optional[dict[str, Any]] = None,
) -> CheckResult:
    """Verify a finalised audit-session pack's events.jsonl.

    A session pack holds a selection of the workspace chain, so the events are
    not a contiguous run and prev_hash links to events that are not in the file.
    Gaps are expected and stated. What is checked instead, per event:
      1. its event_hash recomputes from its own bytes;
      2. a signed record checkpoint (the chain-root signer's signature over this
         event's sequence number and hash, the same one the single-record proof
         uses) names it, verified against the pinned keys;
      3. events are in ascending sequence order, with no duplicate, and no
         checkpoint is left without its event (an event removed from the file
         leaves its checkpoint behind).
    """
    result = CheckResult(check="hash_chain_integrity", status="PASS")
    if not events:
        result.status = "FAIL"
        result.anomalies.append({"kind": "empty_events", "message": "events.jsonl carries no events; nothing to verify"})
        return result
    result.count = len(events)

    def fail(kind: str, message: str, **extra: Any) -> None:
        result.status = "FAIL"
        result.anomalies.append({"kind": kind, "message": message, **extra})

    if not isinstance(doc, dict) or doc.get("version") != SESSION_CHECKPOINTS_VERSION or doc.get("scope") != "audit_session":
        fail("session_checkpoints_malformed",
             f"{SESSION_CHECKPOINTS_FILE} is not a {SESSION_CHECKPOINTS_VERSION} audit_session attestation")
        return result
    cps_raw = doc.get("checkpoints")
    if cps_raw is None:
        cps_raw = []  # no signer at export: nothing attests the events (each fails below)
    if not isinstance(cps_raw, list):
        fail("session_checkpoints_malformed", f"{SESSION_CHECKPOINTS_FILE} carries no checkpoints list")
        return result
    # The pack must name its session, and that session's own event must be in it.
    session_id = str((manifest or {}).get("session_id") or "")
    if not session_id or not any(
        e.get("entity_type") == "audit_session" and e.get("entity_id") == session_id for e in events
    ):
        fail("session_pack_not_a_session",
             "session_checkpoints.json is present but the manifest names no audit session whose event is in "
             "events.jsonl; a full-chain export carries no such file")
    # One workspace only: the checkpoints, the signed root and every event must agree.
    tenants = {str(e.get("tenant_id") or "") for e in events}
    tenants.add(str(doc.get("tenant_id") or ""))
    if chain_root is not None and (chain_root.get("signature") or ""):
        tenants.add(str(chain_root.get("tenant_id") or chain_root.get("TenantID") or ""))
    if len(tenants) != 1 or "" in tenants:
        fail("session_tenant_mismatch",
             "the events, the checkpoints and the signed chain root do not all name the same workspace")
    cps: dict[int, dict[str, Any]] = {}
    for cp in cps_raw:
        try:
            n = int(cp.get("sequence_number"))
        except (TypeError, ValueError, AttributeError):
            fail("session_checkpoints_malformed", "a checkpoint carries no sequence number")
            continue
        if n in cps:
            fail("session_checkpoint_duplicate", "two checkpoints name the same sequence number", sequence_number=n)
        cps[n] = cp

    prior_seq: Optional[int] = None
    prior_hash: Optional[str] = None
    seen: set[int] = set()
    linked = 0
    degraded = False
    for ev in events:
        seq_raw = ev.get("sequence_number")
        try:
            seq = int(seq_raw)
        except (TypeError, ValueError):
            fail("sequence_number_unparseable", "event carries a non-integer sequence_number", event_id=ev.get("event_id"))
            continue
        if seq in seen:
            fail("sequence_number_duplicate", "two events share a sequence_number", sequence_number=seq)
            continue
        seen.add(seq)
        if prior_seq is not None and seq < prior_seq:
            fail("session_events_out_of_order",
                 "events.jsonl is not in ascending sequence order; an event was moved",
                 sequence_number=seq, event_id=ev.get("event_id"))
        stored = ev.get("event_hash") or ""
        withheld = is_withheld_entry(ev)
        if withheld:
            fail("withheld_entry_malformed", withheld, sequence_number=seq, event_id=ev.get("event_id"))
        if withheld is None:
            try:
                computed = base64.b64encode(compute_event_hash(ev)).decode("ascii")
            except Exception as e:  # noqa: BLE001
                fail("hash_compute_error", f"could not recompute hash: {e}", sequence_number=seq, event_id=ev.get("event_id"))
                continue
            if computed != stored:
                fail("event_hash_mismatch",
                     "event_hash does not match recomputation; event payload, header field, or hash was modified",
                     sequence_number=seq, event_id=ev.get("event_id"))
        cp = cps.pop(seq, None)
        if cp is None:
            fail("session_event_unattested",
                 "no signed checkpoint attests this event; it cannot be bound to the signed chain",
                 sequence_number=seq, event_id=ev.get("event_id"))
        else:
            sub = check_record_checkpoint_signature({"checkpoint": cp, "event": ev}, trusted_keys)
            if sub.status == "FAIL":
                for a in sub.anomalies:
                    fail("session_" + str(a.get("kind", "checkpoint_failed")), str(a.get("message", "")),
                         sequence_number=seq, event_id=ev.get("event_id"))
            elif sub.status == "DEGRADED":
                degraded = True
                for n in sub.notes:
                    if n not in result.notes:
                        result.notes.append(n)
        if prior_hash is not None and (ev.get("prev_hash") or "") == prior_hash:
            linked += 1
        prior_seq = seq if prior_seq is None else max(prior_seq, seq)
        prior_hash = stored
    for seq in sorted(cps):
        fail("session_checkpoint_orphan",
             "a signed checkpoint names an event that is not in events.jsonl; an event was removed",
             sequence_number=seq)
    if result.status == "PASS":
        if degraded:
            result.status = "DEGRADED"
        gaps = max(len(events) - 1 - linked, 0)
        result.notes.append(
            f"audit-session pack: verified {len(events)} events; every hash recomputes and every event "
            f"is attested by a signed checkpoint. This is a selection of the workspace chain, so gaps "
            f"between events are expected ({gaps} here) and are not a failure. The check does not show "
            f"that no event was left out of, or added to, the selection"
        )
    return result


# ---------------------------------------------------------------------------
# Check 1b - chain completeness (independent of the hash-linkage walk)
# ---------------------------------------------------------------------------

# The `version` marker on the signed chain root decides whether chain_length is
# an independently checkable event COUNT. A v2 root signs chain_length == the
# tenant's OWN event count, so `chain_length == events_seen` is a real
# completeness invariant: it catches an omitted, truncated, or injected event
# WITHOUT relying on the hash-linkage walk (a second, independent witness). A v1
# (legacy, no `version` field) root signs a GLOBAL head sequence into
# chain_length, which is NOT the event count, so the equality is deliberately
# NOT asserted there - a documented schema limitation, not a fault (a
# pre-Amendment-2 bundle must still verify, exit 0). Sequence numbers are a
# shared global BIGSERIAL: unique per commit but NOT contiguous 1..N for one
# tenant (other tenants' events consume values in between), so contiguity is
# deliberately NOT asserted - only a DUPLICATE sequence number is flagged, which
# signals a duplicated/injected event regardless of version. Per event_hash.py's
# versioned-signature rules and the SeqNotEqualCount / BackCompat_LegacyV1Root
# integration guarantees.
CHAIN_ROOT_V2 = "v2"
# "v3" (Amendment 17): the same signed fields and the same tenant-event-count meaning as "v2", plus the
# signed claim that the package carrying this root is sealed.
CHAIN_ROOT_V3 = "v3"
CHAIN_ROOT_VERSIONS = ("v1", CHAIN_ROOT_V2, CHAIN_ROOT_V3)
# Roots whose signed highest_seq is the tenant's own event count (every reader of "v2" reads "v3" the same way).
TENANT_PURE_ROOT_VERSIONS = (CHAIN_ROOT_V2, CHAIN_ROOT_V3)

# The ONE integer wire grammar the completeness witness accepts, applied
# byte-for-byte identically in verify.py and verify.mjs so the two verifiers
# never disagree. Python int() and JS Number() otherwise diverge on non-canonical
# wire values (1.5, true, "1e0"), which would verdict a malformed count/sequence
# differently across them. The shared grammar: a JSON integer number, OR a plain
# decimal-integer string (optional leading '-', ASCII digits only). Rejected:
# booleans, fractional numbers (1.5), exponent/hex/whitespace strings ("1e0"),
# and non-numeric junk. An integer-valued float (2.0) is accepted as 2. A
# magnitude beyond the JS safe-integer range (2**53-1) is classified "unsafe"
# identically in both - Python has arbitrary ints but JSON.parse in JS is lossy
# past 2**53, so neither verifier trusts such a value rather than disagree on it.
_SAFE_INT_MAX = 2 ** 53 - 1


def _is_decimal_int_string(s: str) -> bool:
    """True iff s is '-'?<one-or-more ASCII digits> - no exponent, sign-only,
    whitespace, or unicode digits. ASCII-only to match JS's [0-9]."""
    body = s[1:] if s[:1] == "-" else s
    return len(body) > 0 and all("0" <= c <= "9" for c in body)


def _canonical_int(raw: Any) -> tuple[str, Optional[str]]:
    """Classify a wire value under the shared integer grammar.

    Returns ("ok", canonical_decimal_str) | ("unsafe", None) | ("bad", None).
    Mirror of verify.mjs canonicalInt - the two MUST stay identical.
    """
    if isinstance(raw, bool):
        return ("bad", None)
    if isinstance(raw, int):
        v = raw
    elif isinstance(raw, float):
        if not raw.is_integer():
            return ("bad", None)
        if abs(raw) > _SAFE_INT_MAX:
            return ("unsafe", None)
        v = int(raw)
    elif isinstance(raw, str):
        if not _is_decimal_int_string(raw):
            return ("bad", None)
        v = int(raw)
    else:
        return ("bad", None)
    if abs(v) > _SAFE_INT_MAX:
        return ("unsafe", None)
    return ("ok", str(v))


def check_chain_completeness(
    events: list[dict[str, Any]],
    chain_root: Optional[dict[str, Any]],
    session_mode: bool = False,
) -> CheckResult:
    """Assert the events set is complete, independently of hash linkage.

    Two witnesses that do not depend on recomputing the hash chain:
      1. Sequence numbers are unique (a duplicate is a duplicated/injected
         event). Applies to every bundle.
      2. For a v2 chain root only, the signed tenant event count
         (chain_length) equals the number of events walked - so an event
         omitted, truncated, or injected after signing is caught even if the
         remaining events still form a valid hash chain. A v1/legacy root's
         chain_length is a global head sequence, not a count, so this witness
         is not applicable there (documented limitation; never a FAIL).
    """
    result = CheckResult(check="chain_completeness", status="PASS")
    events_seen = len(events)
    result.count = events_seen
    if not events:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "empty_events",
            "message": (
                "events.jsonl carries no events; nothing to check for "
                "completeness"
            ),
        })
        return result

    # 1) Unique sequence numbers under the shared integer grammar. A value that
    #    is not a canonical integer, or a duplicate, is a completeness fault
    #    independent of the hash chain.
    seen: set[str] = set()
    unsafe_seq = 0
    for ev in events:
        state, canon = _canonical_int(ev.get("sequence_number"))
        if state == "bad":
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "sequence_number_unparseable",
                "event_id": ev.get("event_id"),
                "sequence_number": ev.get("sequence_number"),
                "message": (
                    "event carries a missing or non-canonical-integer "
                    "sequence_number (booleans, fractions, and exponent "
                    "strings are rejected); chain completeness cannot be "
                    "established"
                ),
            })
            continue
        if state == "unsafe":
            unsafe_seq += 1
            continue
        if canon in seen:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "sequence_number_duplicate",
                "sequence_number": canon,
                "message": (
                    "two events share a sequence_number; an event was "
                    "duplicated or injected"
                ),
            })
        seen.add(canon)
    if unsafe_seq:
        result.notes.append(
            f"{unsafe_seq} sequence number(s) exceed the verifier's "
            "safe-integer range (2**53-1) and were excluded from the "
            "uniqueness witness; the hash-chain linkage check still bounds them."
        )

    # 2) Independent count witness, version-gated on the signed root.
    if session_mode:
        # A finalised audit-session pack carries a selection of the workspace
        # chain, so the signed workspace count is NOT the number of events here
        # It is still an upper bound: a selection cannot hold more events than
        # the workspace chain the root signed (v2 roots only).
        if chain_root is not None and str(chain_root.get("version") or chain_root.get("Version") or DEFAULT_CHAIN_ROOT_VERSION) in TENANT_PURE_ROOT_VERSIONS:
            state, canon = _canonical_int(chain_root.get("chain_length", chain_root.get("ChainLength")))
            if state == "ok" and events_seen > int(canon):
                result.status = "FAIL"
                result.anomalies.append({
                    "kind": "chain_length_exceeded",
                    "chain_length": int(canon),
                    "events_seen": events_seen,
                    "message": "this selection holds more events than the signed workspace chain; events were injected",
                })
        result.notes.append(
            "audit-session pack: the signed workspace chain length is not the "
            "number of events in this selection, so the count witness does not "
            "apply; every included event is attested by its own signed checkpoint"
        )
    elif chain_root is None:
        result.notes.append(
            "no chain_root.json present; the independent count witness "
            "(chain_length == events walked) needs the signed root and was "
            "skipped - the hash-chain and chain-root-signature checks still "
            "bound completeness."
        )
    else:
        version = str(
            chain_root.get("version")
            or chain_root.get("Version")
            or DEFAULT_CHAIN_ROOT_VERSION
        )
        raw_len = chain_root.get("chain_length")
        if raw_len is None:
            raw_len = chain_root.get("ChainLength")
        if version in TENANT_PURE_ROOT_VERSIONS:
            state, canon = _canonical_int(raw_len)
            if state == "bad":
                result.status = "FAIL"
                result.anomalies.append({
                    "kind": "chain_length_unparseable",
                    "chain_length": raw_len,
                    "message": (
                        "v2 chain_root.chain_length is missing or not a "
                        "canonical integer (booleans, fractions, and exponent "
                        "strings are rejected); the signed tenant event count "
                        "cannot be verified"
                    ),
                })
            elif state == "unsafe":
                result.status = "FAIL"
                result.anomalies.append({
                    "kind": "chain_length_unsafe_range",
                    "chain_length": raw_len,
                    "events_seen": events_seen,
                    "message": (
                        "v2 chain_root.chain_length exceeds the verifier's "
                        "safe-integer range (2**53-1); a real tenant event "
                        "count is small, so this value is corrupt or mislabeled"
                    ),
                })
            else:
                chain_length = int(canon)
                if chain_length != events_seen:
                    result.status = "FAIL"
                    result.anomalies.append({
                        "kind": "chain_length_mismatch",
                        "chain_length": chain_length,
                        "events_seen": events_seen,
                        "message": (
                            "the signed v2 chain root attests a tenant event "
                            f"count of {chain_length} but events.jsonl carries "
                            f"{events_seen}; events were omitted, truncated, or "
                            "injected after signing"
                        ),
                    })
                else:
                    result.notes.append(
                        "independent count witness: the signed v2 chain root's "
                        f"tenant event count ({chain_length}) matches the "
                        f"{events_seen} events walked"
                    )
        else:
            result.notes.append(
                "legacy v1 chain root: chain_length is a global head sequence, "
                "not the tenant event count, so the independent count witness "
                "is not applicable (documented limitation). v1 completeness "
                "rests on the hash-chain linkage and the chain-root head-hash "
                "signature checks."
            )

    if result.status == "PASS" and not result.anomalies:
        result.notes.append(
            f"verified {events_seen} events carry unique sequence numbers "
            "with no duplicated or injected entry"
        )
    return result


# ---------------------------------------------------------------------------
# Check 2 - chain-root signature
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Trust anchor. The chain-root / checkpoint signature is verified
# against a PINNED set of Kanonik public keys, never against the key the bundle
# ships. prod / int / local all use signing_key_id "chain-root:v1@vault" with
# DIFFERENT keys, so the entry is chosen by which pinned key VERIFIES the
# signature, and its env decides the verdict: production -> PASS; dev ->
# DEGRADED (not production-attested); none verify -> FAIL. When no pinned set is
# available at all the verifier falls back to the bundle's own key but DEGRADES,
# never a silent PASS.
# ---------------------------------------------------------------------------

DEFAULT_TRUSTED_KEYS_PATH = Path(__file__).resolve().parent / "trusted_keys.json"
# The pinned trust anchors live INSIDE this file (A5-001), as DEFAULT_TRUSTED_KEYS does in verify.mjs and verify.html.
# trusted_keys.json beside the checker is only the distribution copy for diffing against kanonik-verify; it is never
# read as an anchor, so someone who re-signs a package with their own key cannot make it pass by swapping that file
# (use --trusted-keys to add keys on purpose). A test keeps these keys identical to trusted_keys.json (minus its prose _comment).
PINNED_TRUSTED_KEYS_JSON = r'''{
  "schema": "kanonik-chain-root-keys/v2",
  "min_key_file_signed_at": "2026-10-24T00:00:00Z",
  "revoked_keys": [],
  "keys": [
    {
      "signing_key_id": "chain-root:v1@vault",
      "env": "production",
      "sha256_spki_der": "4037e409f864b8149b9f5d021122e1fd2bea3bbec1504a1e2716ba1411c5df1d",
      "seal_required_from": "2026-11-01T00:00:00Z",
      "pem": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEaoCdQeFBb/tAPcfs54JU/VxMzbA05ua5\noSBkuvKnl5wS5GPqIpekksoA/ZmU28E7tAmwjKpI+zpDtIN+ET+rjIM27JnRD8fr\n6d13DzGlJED1n7z0nyXWhOsYaQetPxwf\n-----END PUBLIC KEY-----\n",
      "status": "active"
    },
    {
      "signing_key_id": "chain-root:v1@vault",
      "env": "dev",
      "label": "integration",
      "sha256_spki_der": "7b7dba090c3c7168d7880b95144b25e436ce01e63350e69aa164857390acbc84",
      "seal_required_from": "2026-10-22T00:00:00Z",
      "pem": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEW+lI5s8xYdwpEVZNEGa091bltFFIRImb\n65Dz/f3gSP1IUz8uagVDaaDYJZ70d/XQ82DM9VOrfGLpAoKj0/gXPX8aDHJeGqsE\nDUW3c5lvcMuIik8klFQvpo2YHyh1oK7W\n-----END PUBLIC KEY-----\n",
      "status": "active"
    },
    {
      "signing_key_id": "kanonik-public-sample-2026-10-04",
      "class": "sample",
      "env": "sample",
      "label": "Kanonik public sample key - synthetic data only",
      "sha256_spki_der": "bd2689adf99a28d57e1a0174a3bc835b772ef02b437a5a59f9fd3bbd19fe277f",
      "seal_required_from": "2026-01-01T00:00:00Z",
      "pem": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuCibNIPNWVpJhXkG/obwIJbfood2ITdU\nuaKKdminUNxMkYqxY1bt3/3qVV7cyOXZsViP9Z5ZTUsRFm+mDVMVGIi9PlqtUPJx\n4uVrJzXw8vALKJMS1Moq7CXNQ74ZeOhs\n-----END PUBLIC KEY-----\n",
      "status": "active"
    }
  ],
  "skill_signing_keys": [
    {
      "signing_key_id": "sha256:068fb03acc0367e508ce0da187ccca9d37cdd11c499dc2ae2dd6a2bcda627e84",
      "env": "production",
      "label": "kanonik-first-party",
      "sha256_spki_der": "068fb03acc0367e508ce0da187ccca9d37cdd11c499dc2ae2dd6a2bcda627e84",
      "pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExjLB9vqUvtWH8eNCvUpEU5Tlwurm\n4FLNVJABg1P8X+H/4PqnMWwZCRybLPhAnsoLfPmtZ8qvH0oI+WPFMRIIig==\n-----END PUBLIC KEY-----\n"
    }
  ]
}'''
SHIPPED_TRUSTED_KEYS_DOC: dict[str, Any] = json.loads(PINNED_TRUSTED_KEYS_JSON)
WELL_KNOWN_KEYS_URL = "https://kanonik.ai/.well-known/kanonik-chain-root-keys.json"


def _coerce_pem(pem: Any) -> Optional[bytes]:
    if isinstance(pem, bytes):
        return pem
    if isinstance(pem, str) and pem.strip():
        return pem.encode("utf-8")
    return None


def load_trusted_keys_report(
    override_path: Optional[Path] = None,
    online: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Load the pinned trust anchors: the key list built into this file, an optional
    override file, and (online) the well-known published set. Best-effort: a
    missing or unreadable source contributes nothing. Each entry is
    {signing_key_id, env, label, pem(bytes), sha256_spki_der, status}.

    The second value says what --online did, so a report never looks the same when revocation was not checked:
    {"state": "not_requested" | "used" | "rejected" | "unreachable", "note": "..."}.
    """
    keys: list[dict[str, Any]] = []
    floor = ""
    revoked_docs: list[Any] = []

    def _ingest(doc: Any) -> None:
        if not isinstance(doc, dict):
            return
        for k in doc.get("keys", []) or []:
            if not isinstance(k, dict):
                continue
            entry = _key_entry(k)
            if entry is not None:
                keys.append(entry)
        revoked_docs.append(doc)

    _ingest(SHIPPED_TRUSTED_KEYS_DOC)
    shipped_floor = SHIPPED_TRUSTED_KEYS_DOC.get("min_key_file_signed_at")
    if isinstance(shipped_floor, str) and _SIGNED_AT.fullmatch(shipped_floor):
        floor = shipped_floor
    if override_path is not None:
        try:
            if override_path.exists():
                _ingest(json.loads(override_path.read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            pass
    for d in revoked_docs:
        keys[:] = _apply_revoked(keys, d)

    report = {"state": "not_requested", "note": ""}
    if online:
        try:
            with _urlopen_no_redirect(urllib.request.Request(WELL_KNOWN_KEYS_URL)) as resp:
                raw = resp.read(KEY_FILE_MAX_BYTES + 1)
            if len(raw) > KEY_FILE_MAX_BYTES:
                raise ValueError("the key file is larger than this checker reads")
            fetched = json.loads(raw.decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            report = {"state": "unreachable", "note": f"the online key file could not be read ({type(e).__name__}): key revocations were NOT checked; only the keys pinned in this checker were used"}
        else:
            merged, mode, note = merge_key_file(_consolidate_keys(keys), fetched, floor)
            if mode == "continuity":
                keys[:] = merged
                report = {"state": "used", "note": "the online key file is signed by a pinned Kanonik key and was applied"}
            else:
                report = {"state": "rejected", "note": f"{note}; key revocations were NOT checked; only the keys pinned in this checker were used"}

    return _consolidate_keys(keys), report


def load_trusted_keys(
    override_path: Optional[Path] = None,
    online: bool = False,
) -> list[dict[str, Any]]:
    return load_trusted_keys_report(override_path, online)[0]


def online_keys_line(report: Optional[dict[str, str]]) -> str:
    """One printable line for the online key file result ("" when --online was not asked)."""
    if not report or report.get("state") == "not_requested":
        return ""
    word = {"used": "used", "rejected": "REJECTED", "unreachable": "UNREACHABLE"}.get(report.get("state", ""), "unknown")
    return f"Online key file: {word}. {report.get('note', '')}"


def _verify_sig_against_trusted(
    signature: bytes,
    signed_payload: bytes,
    trusted_keys: list[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """Return the trusted-key entry whose public key verifies the signature
    (ECDSA P-384 + SHA-384), or None if none do. The bundle's own key is never
    consulted here."""
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
        load_pem_public_key,
    )
    for k in _consolidate_keys(trusted_keys):
        if k.get("status") == "revoked":
            continue  # a revoked key vouches for nothing it ever signed
        pem = _coerce_pem(k.get("pem"))
        if pem is None:
            continue
        try:
            pub = load_pem_public_key(pem)
            if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP384R1):
                continue
            pub.verify(signature, signed_payload, ec.ECDSA(hashes.SHA384()))
            return k
        except Exception:  # noqa: BLE001
            continue
    return None


def _verifying_keys(
    signature: bytes,
    signed_payload: bytes,
    trusted_keys: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Every trusted-key entry whose public key verifies the signature (the same test as
    _verify_sig_against_trusted, without stopping at the first)."""
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.hazmat.primitives.serialization import load_pem_public_key  # noqa: PLC0415
    found: list[dict[str, Any]] = []
    for k in _consolidate_keys(trusted_keys):
        if k.get("status") == "revoked":
            continue
        pem = _coerce_pem(k.get("pem"))
        if pem is None:
            continue
        try:
            pub = load_pem_public_key(pem)
            if isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP384R1):
                pub.verify(signature, signed_payload, ec.ECDSA(hashes.SHA384()))
                found.append(k)
        except Exception:  # noqa: BLE001
            continue
    return found


def _canonical_b64(value: Any) -> bytes:
    """Decode canonical base64 only: the standard alphabet, padded, and the exact string the encoder would write
    (no stray character, no extra padding, no non-zero padding bits). verify.mjs reads a chain-root signature
    the same way, so one string cannot read signed in one checker and unsigned in the other."""
    if not isinstance(value, str):
        raise ValueError("not a string")
    raw = base64.b64decode(value, validate=True)
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("base64 is not canonical")
    return raw


def check_chain_root_signature(
    chain_root: Optional[dict[str, Any]],
    public_key_pem: Optional[bytes],
    events: list[dict[str, Any]],
    trusted_keys: Optional[list[dict[str, Any]]] = None,
    session_mode: bool = False,
) -> CheckResult:
    """Verify the bundled chain_root.json ECDSA P-384 / SHA-384 signature
    against the PINNED Kanonik keys (trusted_keys). The bundle's own
    public_key.pem is used to verify only when no pinned key exists at all,
    and that result is DEGRADED, never PASS. (run_all_checks may load the
    file; it is ignored whenever a pinned key is available.)
    """
    result = CheckResult(check="chain_root_signature", status="PASS")
    if chain_root is None:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "chain_root_missing",
            "message": "chain_root.json not in bundle",
        })
        return result

    root_version = str(chain_root.get("version") or chain_root.get("Version") or DEFAULT_CHAIN_ROOT_VERSION)
    if root_version not in CHAIN_ROOT_VERSIONS:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "chain_root_version_unknown",
            "message": (
                f"this package's chain root has version {root_version!r}, which this checker does not know. "
                "Use a current checker; do not read the package as an older one."
            ),
        })
        return result

    sig_b64 = chain_root.get("signature") or ""
    if not sig_b64:
        # Amendment 17: an unsigned root is not a pass. Every package Kanonik exports is signed, and a
        # blanked signature is how a sealed package would be made to look like an older, unsealed one.
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "chain_root_unsigned",
            "message": (
                "chain_root.json has no signature, so Kanonik did not attest to this package's chain. A package "
                "Kanonik exports is always signed; if this one was, the signature was removed. Do not rely on "
                "this package."
            ),
        })
        return result

    try:
        # Strict (canonical) base64, as the seal and withheld-positions checks read theirs, and exactly as verify.mjs
        # reads it: a loosely decoded signature is how the two checkers would come to read one root two ways.
        signature = _canonical_b64(sig_b64)
    except Exception as e:  # noqa: BLE001
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "signature_b64_invalid",
            "message": f"chain_root.signature is not valid base64: {e}",
        })
        return result

    # ECDSA P-384 + SHA-384 verification requires the `cryptography`
    # PyPI library (Python's stdlib only does RSA/HMAC). If absent,
    # DEGRADE the check; the rest of the bundle's tier-2/3 claims
    # still hold.
    try:
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
            load_pem_public_key,
        )
    except ImportError:
        result.status = "DEGRADED"
        result.notes.append(
            "cryptography library not installed; cannot verify the "
            "ECDSA P-384 chain-root signature offline. "
            "Install with `pip install -r requirements.txt`. "
            "Hash-chain integrity (check #1) still establishes that the "
            "events have not been tampered with relative to each other; "
            "the signature gates whether KANONIK ATTESTS to the chain "
            "root at the bundled timestamp."
        )
        return result

    try:
        signed_payload = build_chain_root_signed_payload(chain_root)
    except Exception as e:  # noqa: BLE001
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "signed_payload_rebuild_failed",
            "message": f"could not reconstruct signed payload: {e}",
        })
        return result

    # Verify the signature against the PINNED trust anchor, never the
    # key the bundle ships.
    trusted_keys = trusted_keys or []
    matched: Optional[dict[str, Any]] = None
    if trusted_keys:
        matched = _verify_sig_against_trusted(signature, signed_payload, trusted_keys)
        if matched is None:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "chain_root_key_untrusted",
                "signing_key_id": chain_root.get("signing_key_id") or "",
                "message": (
                    "the chain-root signature does not verify against any "
                    "PINNED Kanonik key (trusted_keys.json / --trusted-keys / "
                    "--online). The bundle may be re-signed with a foreign key, "
                    "tampered, or signed by a key not yet pinned. The bundle's "
                    "own signing_public_key_pem is intentionally NOT trusted."
                ),
            })
            return result
    else:
        # No pinned trust anchor at all: fall back to the bundle's own key, but
        # DEGRADE - this is not an independent verification.
        if public_key_pem is None or not public_key_pem.strip():
            inline = chain_root.get("signing_public_key_pem") or ""
            if isinstance(inline, str) and inline:
                try:
                    public_key_pem = base64.b64decode(inline)
                except Exception as e:  # noqa: BLE001
                    result.status = "FAIL"
                    result.anomalies.append({
                        "kind": "inline_public_key_b64_invalid",
                        "message": f"signing_public_key_pem invalid: {e}",
                    })
                    return result
            else:
                result.status = "FAIL"
                result.anomalies.append({
                    "kind": "public_key_missing",
                    "message": (
                        "no pinned trust anchor and no key in the bundle; "
                        "cannot verify the signature offline"
                    ),
                })
                return result
        try:
            pub = load_pem_public_key(public_key_pem)
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                raise ValueError(
                    f"expected ECDSA public key, got {type(pub).__name__}"
                )
            pub.verify(signature, signed_payload, ec.ECDSA(hashes.SHA384()))
        except Exception as e:  # noqa: BLE001
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "signature_verification_failed",
                "message": (
                    "ECDSA P-384 + SHA-384 signature does NOT verify against "
                    f"the bundled public key ({e})"
                ),
            })
            return result
        result.status = "DEGRADED"
        result.notes.append(
            "no pinned Kanonik trust anchor was available (trusted_keys.json "
            "missing and no --trusted-keys/--online), so the signature was "
            "verified only against the key the BUNDLE carries. That is not an "
            "independent check; fetch the canonical verifier for the pinned "
            "keys."
        )

    # Cross-check: head_event_hash on the chain root should match the
    # event_hash of the highest-sequence event. A tamper check independent of
    # the key, so it applies in every branch except a session pack (a selection,
    # whose last event is not the chain head).
    if events and not session_mode:
        last = max(events, key=lambda e: int(e.get("sequence_number", 0)))
        head_b64 = chain_root.get("head_event_hash") or ""
        last_b64 = last.get("event_hash") or ""
        if head_b64 != last_b64:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "chain_root_head_mismatch",
                "head_event_hash_b64": head_b64,
                "last_event_hash_b64": last_b64,
                "message": (
                    "chain_root.head_event_hash does not match the "
                    "event_hash of the highest-sequence event; events "
                    "may have been added or removed after signing"
                ),
            })
            return result

    if matched is not None:
        env = matched.get("env") or ""
        if matched.get("class") == "sample":
            result.status = "DEGRADED"
            result.notes.append(SAMPLE_KEY_NOTE)
        elif env == "production":
            result.notes.append(
                "ECDSA P-384 + SHA-384 signature verified against Kanonik's "
                "PINNED PRODUCTION signing key (id "
                f"{matched.get('signing_key_id')!r}); chain root attestable to "
                f"Kanonik as of {chain_root.get('signed_at')}"
            )
        else:
            result.status = "DEGRADED"
            label = matched.get("label") or env or "non-production"
            result.notes.append(
                "signature verified against a pinned NON-PRODUCTION Kanonik key "
                f"(env={env or 'dev'}, {label}); the chain root is structurally "
                "sound but is NOT attestable to Kanonik's PRODUCTION signing "
                "key. Expected for integration/dev bundles."
            )
    return result


# ---------------------------------------------------------------------------
# Check 3 - Verifier verdict presence
# ---------------------------------------------------------------------------


# Committed-event families and HOW each is Verifier-graded. Sourced from the
# canonical model's committed-event constants. Coverage is EXHAUSTIVE and
# FAIL-CLOSED: a `*.committed.v1` event whose kind is absent from every set
# below FAILs (committed_kind_unclassified), so a newly-shipped committed kind
# cannot silently slip through unverified.

# The Verifier verdict lives INSIDE the committed event as a required field of
# the canonical schema; the model rejects one sealed without it. So an absent
# embedded verdict is a forged / corrupt event -> FAIL.
COMMITTED_EMBEDDED_REQUIRED = {
    "mapping.committed.v1",
    "link.committed.v1",
    "claim.committed.v1",
    "audit.finding.recorded.v1",
    # An operational fact is graded by the shared soundness Verifier
    # and its verdict is a required field of the sealed payload (2.7.2).
    "operational_fact.committed.v1",
}

# Graded kinds that emit a standalone verifier.verdict.v1 and have ALWAYS
# carried a verdict (checked before this coverage pass, proven safe). An absent
# verdict is a real Verifier-bypass -> FAIL. They MAY also carry an embedded
# verdict (a later additive anchor); it is accepted when present.
COMMITTED_VERDICT_REQUIRED = {
    "internal_control.committed.v1",
    "policy.committed.v1",
    "procedure.committed.v1",
}

# Graded kinds whose canonical schema gained the verdict field only later, so
# events sealed BEFORE it legitimately carry NO verdict (embedded or standalone)
# and must still verify byte-identically. An absent verdict on these DEGRADES
# (surfaced honestly as "no anchored verdict, not independently attestable"),
# never FAILs, so a legitimate full-chain export of an established tenant is not
# broken. A verdict that IS present but rejected still FAILs. New writes can be
# tightened to FAIL later via schema version - see the follow-up.
COMMITTED_VERDICT_HISTORICAL_OPTIONAL = {
    "asset.committed.v1",
    "risk.committed.v1",
    "vendor.committed.v1",
    "soa_decision.committed.v1",
    # An audit session is graded under the audit purpose before mint and embeds
    # the verdict, but sessions sealed before that field existed carry none;
    # an embedded or paired standalone verdict is accepted, an absent one
    # DEGRADES (2.7.4).
    "audit.session.created.v1",
}

# Committed kinds with NO model verdict BY DESIGN - a grouping / envelope /
# rule-only seal whose graded content lives elsewhere. Requiring a verdict on
# the parent would force-fail every legitimate such bundle; its members carry
# the verdicts and are checked in their own right.
COMMITTED_VERDICT_EXEMPT = {
    # An answer set is rule-tier only; its graded content is the claims its
    # entries cite (proof status verified_without_llm_verdict_by_design).
    "questionnaire_response.committed.v1",
    # The generic external-write envelope; it materialises into the entity
    # `*.committed.v1` events, which carry the verdicts.
    "canonical.write.committed.v1",
    # The parent seal of a package: it GROUPS its members under one approval,
    # it never substitutes for them. Every member still emits its own Verifier
    # verdict + `*.committed.v1`; the unit seal itself carries none by design.
    "package_unit.committed.v1",
}

# Human-decision writes that are NOT *.committed.v1 events and carry NO model
# verdict BY DESIGN (2.7.4): the human is the decision and there is no model
# output to gate, so the Verifier has nothing to grade. They are classified here
# so the skip is counted in the report instead of silent. Kept apart from
# COMMITTED_EVENT_TYPES so the embedded-verdict replay checks do not walk them.
GATED_WRITE_VERDICT_EXEMPT = {
    "evidence.captured.v1",
    "control_test.executed.v1",
    "risk.accepted.v1",
    "remediation.applied.v1",
    "exception.approved.v1",
    # The trust page writes. Each is one person's approved act with no model output to gate; they are
    # classified so the offline check counts them instead of FAILing them as gated_write_unclassified.
    "disclosure.published.v1",
    "access_grant.approved.v1",
    "branding.recorded.v1",
    "nda_text.recorded.v1",
    "standing_summary.published.v1",
    "subprocessor_list.published.v1",
    "third_party_document.recorded.v1",
}
TRUST_PAGE_WRITE_EVENTS = frozenset({
    "disclosure.published.v1", "access_grant.approved.v1", "branding.recorded.v1", "nda_text.recorded.v1",
    "standing_summary.published.v1", "subprocessor_list.published.v1", "third_party_document.recorded.v1",
})


def _trust_write_carries_failed_verdict(payload: dict[str, Any]) -> bool:
    """True when a trust page write carries a verifier verdict that is not a pass. No verdict at all is fine."""
    v = payload.get("verifier_verdict")
    if v is None:
        return False
    if not isinstance(v, dict):
        return True
    if v.get("passed") is True:
        return False
    return str(v.get("outcome") or "").strip().upper() not in ("PASSED", "APPROVED", "PASS")

# Human-record replacements: like the capture/execution they replace, they are
# human decisions that must name the person, though no model verdict is needed.
HUMAN_RECORD_REPLACEMENTS = {"evidence.superseded.v1", "control_test.superseded.v1"}

# A conformance attestation is also a human-decision write, but it CARRIES the
# grade it was attested over (`verdict_outcome`, required APPROVED by the
# canonical contract). It is therefore not exempt: the carried outcome is
# validated, and a REJECTED / missing / non-APPROVED outcome FAILs.
GATED_WRITE_OUTCOME_CHECKED = {
    "conformance.attested.v1",
}

# Lifecycle policy source (lifecycle contract). Run sync_lifecycle.py after edits.
LIFECYCLE_VERDICT_POLICY = {'audit.finding.amended.v1': {'reason': 'A replacement version carries its own grade; the grade of an '
                                        'earlier version does not count.',
                              'stance': 'embedded'},
 'audit.session.finalized.v1': {'reason': 'A completeness check and a reference to the signed chain head; '
                                          'findings are graded on their own.',
                                'stance': 'exempt'},
 'audit.session.state_changed.v1': {'reason': 'The audit session moved to a new state; nothing new in it '
                                              'needs a grade.',
                                    'stance': 'exempt'},
 'claim.review_needed.v1': {'reason': 'An automatic mark that a claim is out of date; no new claim is '
                                      'recorded.',
                            'stance': 'exempt'},
 'claim.superseded.v1': {'reason': 'It points to a replacement record; the replacement is checked on its '
                                   'own.',
                         'stance': 'exempt'},
 'control_test.superseded.v1': {'reason': 'A person replaced an evidence or test record, as when it was '
                                          'first captured; it needs no AI grade.',
                                'stance': 'exempt'},
 'evidence.superseded.v1': {'reason': 'A person replaced an evidence or test record, as when it was first '
                                      'captured; it needs no AI grade.',
                            'stance': 'exempt'},
 'framework.licence.attested.v1': {'reason': 'A person confirmed the licence; no AI judges licensing rights.',
                                   'stance': 'exempt'},
 'lens.applicability.decided.v1': {'reason': 'Checked by a fixed rule before it was recorded, so it needs no '
                                             'AI grade.',
                                   'stance': 'rule'},
 'lens.applicability.superseded.v1': {'reason': 'It points to a replacement record; the replacement is '
                                                'checked on its own.',
                                      'stance': 'exempt'},
 'lens.decided.v1': {'reason': 'Checked by a fixed rule before it was recorded, so it needs no AI grade.',
                     'stance': 'rule'},
 'lens.decision.superseded.v1': {'reason': 'It points to a replacement record; the replacement is checked on '
                                           'its own.',
                                 'stance': 'exempt'},
 'link.retracted.v1': {'reason': 'A person withdrew a recorded link; it states nothing new, so it needs no '
                                 'AI grade.',
                       'stance': 'exempt'},
 'migration.summary.recorded.v1': {'reason': 'Checked by a fixed rule before it was recorded, so it needs no '
                                             'AI grade.',
                                   'stance': 'rule'},
 'migration.summary.superseded.v1': {'reason': 'It points to a replacement record; the replacement is '
                                               'checked on its own.',
                                     'stance': 'exempt'},
 'obligation.recorded.v1': {'reason': 'Checked by a fixed rule before it was recorded, so it needs no AI '
                                      'grade.',
                            'stance': 'rule'},
 'policy_acknowledgement.recorded.v1': {'reason': 'Checked by a fixed rule before it was recorded, so it '
                                                  'needs no AI grade.',
                                        'stance': 'rule'},
 'obligation.superseded.v1': {'reason': 'It points to a replacement record; the replacement is checked on '
                                        'its own.',
                              'stance': 'exempt'},
 'package.created.v1': {'reason': 'It only groups other records; each record in the group has its own grade.',
                        'stance': 'exempt'},
 'questionnaire_response.superseded.v1': {'reason': 'It points to a replacement record; the replacement is '
                                                    'checked on its own.',
                                          'stance': 'exempt'},
 'soa_decision.revised.v1': {'reason': 'A replacement version carries its own grade; the grade of an earlier '
                                       'version does not count.',
                             'stance': 'embedded'},
 'sod_exception.recorded.v1': {'reason': 'It discloses an approval decision a person made; it is not a new '
                                         'record written by an AI.',
                               'stance': 'exempt'}}


def _signature_words(sig_str: str) -> str:
    """The "Signature verified" value a person reads. The JSON keeps the program word "degraded". Degraded covers a signature that
    verified with notes AND one that could not be checked here (no cryptography library), so the line never says "yes": it says "not fully" and points at the notes."""
    return {"degraded": "not fully (read the notes below)"}.get(sig_str, sig_str)


def _say_json_follows() -> None:
    """One plain line before the JSON a program reads: its DEGRADED is the "Passed with notes" above, not a second verdict."""
    print(
        "\nThe block below is the same result for programs. It says PASS, DEGRADED or FAIL: DEGRADED means Passed with notes.",
        file=sys.stderr,
    )


def _kind_words(et: str) -> str:
    """An event type in words a person reads ("obligation.recorded.v1" -> "obligation recorded"), for the notes."""
    words = re.sub(r"[._]+", " ", re.sub(r"\.v\d+$", "", et))
    # short internal names a person would not know
    return words.replace("sod exception", "separation-of-duties exception").replace("soa decision", "statement of applicability decision")


def _is_unclassified_gated_write(et: str, payload: dict[str, Any]) -> bool:
    """Whether an event is a gated write this verifier does not classify.

    A gated write is an event that carries BOTH an approval token and an
    approver. Committed kinds are handled by the committed coverage pass and the
    approval.* lifecycle is the gate itself, so neither counts.
    """
    if et.endswith(".committed.v1") or et.startswith("approval."):
        return False
    if (
        et in COMMITTED_EVENT_TYPES
        or et in GATED_WRITE_VERDICT_EXEMPT
        or et in GATED_WRITE_OUTCOME_CHECKED
        or et in LIFECYCLE_VERDICT_POLICY
    ):
        return False
    return bool(payload.get("approval_jti") and payload.get("approved_by_subject"))


# An embedded verdict is no weaker than a standalone one: it sits inside a
# hash-chained, signed event, tamper-evident on the same terms, and cannot be
# separated from the thing it justifies. Reading it is reading the anchor that
# exists, not relaxing the check.
EMBEDDED_VERDICT_EVENT_TYPES = COMMITTED_EMBEDDED_REQUIRED

# Every committed kind this verifier recognises. A `*.committed.v1` event
# outside this set is unclassified and FAILs (fail-closed coverage).
COMMITTED_EVENT_TYPES = (
    COMMITTED_EMBEDDED_REQUIRED
    | COMMITTED_VERDICT_REQUIRED
    | COMMITTED_VERDICT_HISTORICAL_OPTIONAL
    | COMMITTED_VERDICT_EXEMPT
)


def _embedded_verdict(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return the verdict embedded in a committed payload, or None.

    Only a MAPPING-shaped verdict object counts: a bare truthy value, or an
    object with no outcome, is treated as absent rather than as a pass. A
    malformed verdict must read as missing, never as satisfied.
    """
    v = payload.get("verifier_verdict")
    if isinstance(v, dict) and v:
        return v
    return None


def _verdict_field_state(payload: dict[str, Any]) -> str:
    """Classify the RAW verifier_verdict field, distinguishing an ABSENT
    optional field from a PRESENT-but-MALFORMED one - a distinction
    _embedded_verdict deliberately collapses (both -> None):

      "absent"    - the key is missing or explicitly null. For a kind whose
                    schema keeps the field optional this is schema-permitted.
      "malformed" - the field is PRESENT but not a valid verdict object: an
                    empty object, an array, a scalar string, a boolean, a
                    number. A garbage verdict is not an absent one; it must
                    FAIL, never degrade, and must do so identically in the JS
                    twin (verdictFieldState in verify.mjs).
      "present"   - a non-empty object (a real verdict; validate its outcome).
    """
    if "verifier_verdict" not in payload:
        return "absent"
    v = payload["verifier_verdict"]
    if v is None:
        return "absent"
    if isinstance(v, dict) and v:
        return "present"
    return "malformed"


_APPROVING_OUTCOMES = {"APPROVED", "PASS", "PASSED"}


def _committed_has_approver(payload: dict[str, Any]) -> bool:
    """Whether a committed event records a human approver.

    Every *.committed.v1 event only exists after the approval gate consumed a
    single-use token, so it carries the subject who clicked and that token's
    jti. Presence of either is proof a human decided.
    """
    return bool(
        payload.get("approved_by_subject")
        or payload.get("approved_by")
        or payload.get("approval_jti")
    )


APPROVAL_OVERRIDE_EVENT_TYPE = "approval.override.recorded.v1"


def _event_seq(event: dict[str, Any]) -> int:
    try:
        return int(event.get("sequence_number", 0))
    except (TypeError, ValueError):
        return 0


def _index_anchored_overrides(
    events: list[dict[str, Any]],
) -> tuple[dict[str, list[tuple[int, dict[str, Any]]]], Optional[int]]:
    """Index every approval.override.recorded.v1 by the committed event it names.

    The override is its own event on the chain, written by the knowledge-service
    when it seals a record over a REJECTED verdict. It names the committed event
    by id, the approver, and the stated reason. The boolean inside the committed
    payload is the audited party's own assertion and is never read as proof.

    Also returns the chain sequence of the FIRST override event, the evidence
    that the chain was writing them from that point on (see
    _historical_inline_override).
    """
    index: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    first_seq: Optional[int] = None
    for ev in events:
        if ev.get("event_type") != APPROVAL_OVERRIDE_EVENT_TYPE:
            continue
        seq = _event_seq(ev)
        if first_seq is None or seq < first_seq:
            first_seq = seq
        payload = _payload(ev)
        target = payload.get("committed_event_id")
        if isinstance(target, str) and target:
            index.setdefault(target, []).append((seq, payload))
    return index, first_seq


def _committed_approver(payload: dict[str, Any]) -> str:
    approver = payload.get("approved_by_subject") or payload.get("approved_by") or ""
    return approver.strip() if isinstance(approver, str) else ""


def _committed_has_override(
    committed: dict[str, Any],
    payload: dict[str, Any],
    overrides: dict[str, list[tuple[int, dict[str, Any]]]],
) -> bool:
    """Whether a committed event's REJECTED verdict was overridden ON THE CHAIN.

    True only when a separate approval.override.recorded.v1 matches the
    committed event by id, was appended after it, names exactly the approver the
    committed event records (a committed event with no approver is never
    matched), and carries a non-blank reason. The inline override_acknowledged
    flag on the committed payload is ignored.
    """
    committed_seq = _event_seq(committed)
    approver = _committed_approver(payload)
    if not approver:
        return False
    for seq, ov in overrides.get(str(committed.get("event_id") or ""), []):
        if seq <= committed_seq:
            continue
        subject = ov.get("approver_subject")
        reason = ov.get("reason")
        if not isinstance(subject, str) or subject != approver:
            continue
        if not isinstance(reason, str) or not reason.strip():
            continue
        return True
    return False


def _historical_inline_override(
    committed: dict[str, Any],
    payload: dict[str, Any],
    overrides: dict[str, list[tuple[int, dict[str, Any]]]],
    first_override_seq: Optional[int],
) -> bool:
    """Whether a REJECTED record is a seal from before overrides were anchored.

    Records sealed before the override event existed could only carry the inline
    flag and reason. That flag is still not proof, so such a record is reported
    DEGRADED (not independently attestable), never PASS. It counts as historical
    only when it states an override with a reason and an approver, NO override
    event names it, and it sits before the first override event on the chain (or
    the chain has none). Once the chain shows the event was being written, an
    inline-only record fails.
    """
    if payload.get("override_acknowledged") is not True:
        return False
    reason = payload.get("override_reason")
    if not isinstance(reason, str) or not reason.strip():
        return False
    if not _committed_approver(payload):
        return False
    if overrides.get(str(committed.get("event_id") or "")):
        return False
    if first_override_seq is not None and _event_seq(committed) > first_override_seq:
        return False
    return True


def _rejected_only(outcomes: list[str]) -> bool:
    """Whether every outcome here is a plain REJECTED (no other failing reason)."""
    return bool(outcomes) and all(
        str(o or "").strip().upper() == "REJECTED" for o in outcomes
    )


def _degrade_historical_override(
    result: CheckResult, c: dict[str, Any], **extra: Any
) -> None:
    """DEGRADED anomaly for a historical inline-only override. A FAIL wins."""
    if result.status != "FAIL":
        result.status = "DEGRADED"
    result.anomalies.append({
        "kind": "committed_override_unanchored_historical",
        "event_id": c.get("event_id"),
        "event_type": c.get("event_type"),
        "message": (
            "this record was sealed over a rejected Verifier verdict and carries "
            "only an override flag and reason inside the record itself; no "
            "override event on the chain names it. It predates chain-anchored "
            "overrides, so it is reported DEGRADED: the override is not "
            "independently attestable, and the flag is not accepted as proof"
        ),
        **extra,
    })


def _outcome_satisfies(
    outcome: str, *, has_approver: bool, has_override: bool
) -> bool:
    """Whether a Verifier outcome lets a committed record legitimately stand.

    The invariant this check protects is that no external write landed WITHOUT
    a Verifier verdict or OVER a rejection, not that every write was
    auto-approved. So:

      APPROVED      -> the Verifier auto-approved.                    passes.
      HUMAN_REVIEW  -> the Verifier deferred below its auto-approve
                       floor and a human approved through the gate.
                       This is the human-in-the-loop happy path,
                       not a bypass.                        passes IFF approver.
      NOT_ASSESSED  -> the Verifier declined to judge (no claim made);
                       it seals on the ordinary click (no override
                       needed).                        passes IFF approver.
      REJECTED      -> a write over a rejection is a violation UNLESS
                       an override event is on the chain.    passes IFF override.
      anything else -> fails closed.
    """
    o = str(outcome or "").strip().upper()
    if o in _APPROVING_OUTCOMES:
        return True
    if o in ("HUMAN_REVIEW", "NOT_ASSESSED"):
        # NOT_ASSESSED: the Verifier declined to judge (the entity made no
        # claim); it seals on the ordinary approval click with no override,
        # so, like HUMAN_REVIEW, a recorded human approver lets it stand.
        return has_approver
    if o == "REJECTED":
        return has_override
    return False


def _standalone_verdict_outcome(payload: dict[str, Any]) -> str:
    """The outcome string of a standalone verifier.verdict.v1.

    Prefers llm_tier_outcome (the graded outcome: approved / human_review /
    rejected); a rule-tier verdict carries no llm outcome, so its `passed`
    boolean maps to APPROVED / REJECTED."""
    o = payload.get("llm_tier_outcome")
    if o:
        return str(o)
    return "APPROVED" if payload.get("passed") is True else "REJECTED"


def _embedded_verdict_outcome(verdict: dict[str, Any]) -> str:
    """The outcome string of an embedded (mapping/v1-shaped) verdict.

    Prefers the top-level `outcome`; a bare `passed: true` (older shape) reads
    as APPROVED. An object with neither reads as "" (fails closed upstream)."""
    o = verdict.get("outcome")
    if o:
        return str(o)
    if verdict.get("passed") is True:
        return "APPROVED"
    return ""

# Proposed-event prefix -> committed-event pairing isn't 1:1 in every
# case, so we anchor the verdict check on the upstream proposal ID
# carried in the verifier verdict payload (related_proposal_id) and
# pair it with proposed events on entity_id.


def _fail_committed(
    result: CheckResult, kind: str, c: dict[str, Any], message: str, **extra: Any
) -> None:
    """Record a hard FAIL anomaly against a committed event."""
    result.status = "FAIL"
    result.anomalies.append({
        "kind": kind,
        "event_id": c.get("event_id"),
        "event_type": c.get("event_type"),
        "message": message,
        **extra,
    })


def _degrade_committed(
    result: CheckResult, c: dict[str, Any], message: str, **extra: Any
) -> None:
    """Record a DEGRADED anomaly: a committed kind that gained its verdict field
    only later carries no anchored verdict. Legitimate for events sealed before
    the field existed, so it is surfaced honestly but never FAILs (a FAIL would
    break a legitimate full-chain export of an established tenant). A FAIL
    already recorded wins - DEGRADED never overrides it.
    """
    if result.status != "FAIL":
        result.status = "DEGRADED"
    result.anomalies.append({
        "kind": "committed_without_verdict_historical",
        "event_id": c.get("event_id"),
        "event_type": c.get("event_type"),
        "message": message,
        **extra,
    })


def _check_lifecycle_verdicts(events: list[dict[str, Any]], result: CheckResult) -> None:
    """Check lifecycle writes separately from committed-kind and chain coverage.

    Exempt means no verdict is required, never that a supplied bad verdict is
    ignored. Rule anchors must precede this seal and name this canonical id;
    batch approval ids and previous versions cannot stand in for the member.
    """
    rule_verdicts: dict[str, list[dict[str, Any]]] = {}
    overrides, _ = _index_anchored_overrides(events)
    for event in events:
        et = event.get("event_type", "")
        payload = _payload(event)
        if et == "verifier.verdict.v1":
            target = payload.get("related_proposal_id")
            if isinstance(target, str) and target:
                rule_verdicts.setdefault(target, []).append(payload)
        if et in GATED_WRITE_VERDICT_EXEMPT | GATED_WRITE_OUTCOME_CHECKED | HUMAN_RECORD_REPLACEMENTS:
            # Producers name the person in approved_by_subject, or approved_by
            # (exception.approved.v1 writes the latter).
            if not _committed_approver(payload):
                _fail_committed(result, "gated_write_without_approver", event,
                                "a human-decision write must name its approver; a token id is not a person")
        policy = LIFECYCLE_VERDICT_POLICY.get(et)
        if policy is None:
            continue
        stance = policy["stance"]
        result.notes.append(f"{_kind_words(et)}: {policy['reason']}")
        state = _verdict_field_state(payload)
        if state == "malformed":
            _fail_committed(result, "lifecycle_malformed_verdict", event,
                            "a supplied lifecycle verdict must be an object with an outcome")
            continue
        embedded = _embedded_verdict(payload)
        if embedded is not None and not _outcome_satisfies(
            _embedded_verdict_outcome(embedded),
            has_approver=bool(_committed_approver(payload)),
            has_override=_committed_has_override(event, payload, overrides),
        ):
            _fail_committed(result, "lifecycle_rejected_verdict", event,
                            "the lifecycle write carries a non-approving verdict without an anchored override")
        if stance == "embedded" and embedded is None:
            _fail_committed(result, "lifecycle_without_verdict", event,
                            "replacement graded content requires its own embedded verdict")
        if stance == "rule":
            anchors = rule_verdicts.get(str(event.get("entity_id") or ""), [])
            # Use the latest rule anchor before the seal: an earlier failure
            # may have been corrected, but a later failure cannot be hidden.
            rules = [v for v in anchors if v.get("tier") == "rule"]
            if not rules or rules[-1].get("passed") is not True:
                _fail_committed(result, "lifecycle_without_rule_verdict", event,
                                "the record requires a preceding passing rule verdict for its canonical id")


# 2.7.22: graded-content pairing. A record the AI re-proposed after the safety check's refinement loop is
# sealed with entity_id = the refinement id and payload.proposal_id = a batch member id, while the standalone verdict
# names the new draft's canonical id, so none of the three ids above meets it. The sealed commit_provenance.verifier
# carries the graded tuple, so the verdict is found by that content, for the always-graded kinds only.
GRADED_CONTENT_PAIRING_KINDS = {
    "internal_control.committed.v1": "internal_control",
    "procedure.committed.v1": "procedure",
    "policy.committed.v1": "policy",
}


def _text(value: Any) -> str:
    # Exact: no trimming, so py and js read an identifier the same way (their trims differ on some characters).
    return value if isinstance(value, str) else ""


def _graded_seq(ev: dict[str, Any]) -> Optional[int]:
    state, canon = _canonical_int(ev.get("sequence_number"))
    return int(canon) if state == "ok" and canon is not None else None


_GRADED_OUTCOME_WORD = re.compile(r"[A-Za-z_]+")


def _graded_outcome(source: dict[str, Any], key: str) -> str:
    """The outcome word of a verdict read by graded content. Only a plain ASCII word counts (anything
    else reads as no outcome, which never satisfies), so py and js cannot read it two ways."""
    o = source.get(key)
    if o is not None and o != "":
        return o if isinstance(o, str) and _GRADED_OUTCOME_WORD.fullmatch(o) else ""
    return "APPROVED" if source.get("passed") is True else ("" if key == "outcome" else "REJECTED")


def _graded_content_outcomes(
    c: dict[str, Any],
    payload: dict[str, Any],
    verdicts_by_cih: dict[str, list[tuple[int, dict[str, Any]]]],
    proposed_by_id: dict[str, list[tuple[int, str, str]]],
    taken: set[int],
    anchors: dict[str, list[tuple[str, Optional[int]]]],
) -> tuple[list[str], bool]:
    """Outcomes of the standalone verdicts that were graded on exactly what this commit sealed.

    Every test must hold, else the list is empty and the caller keeps failing closed: the commit
    records a lineage key (twice, equal), a canonical inputs hash, a prompt content hash, a model and
    a rule pack hash; the verdict has the same four values, the committed record's kind, an earlier
    position in the chain than the commit, and names a proposed event of that kind, earlier than the
    verdict, whose canonical id (or proposal id) it is and whose lineage key is the commit's. A
    verdict an id already pairs to a committed record, or one an earlier commit of the chain already
    matched, is not used again. The caller claims in chain order, for every commit, whichever way it
    is later accepted, so a verdict never serves two commits."""
    kind = GRADED_CONTENT_PAIRING_KINDS.get(str(c.get("event_type")))
    prov = payload.get("commit_provenance")
    if kind is None or not isinstance(prov, dict):
        return [], False
    ver = prov.get("verifier")
    if not isinstance(ver, dict):
        return [], False
    lineage = _text(payload.get("lineage_key"))
    cih = _text(ver.get("canonical_inputs_hash"))
    prompt = _text(ver.get("prompt_content_hash"))
    model = _text(ver.get("model"))
    rule_pack = _text(ver.get("rule_pack_hash"))
    cseq = _graded_seq(c)
    if (
        not lineage or _text(prov.get("lineage_key")) != lineage
        or not cih or not prompt or not model or not rule_pack or cseq is None
    ):
        return [], False
    outcomes: list[str] = []
    used: list[int] = []
    for vseq, vp in verdicts_by_cih.get(cih, []):
        if vseq >= cseq or _text(vp.get("prompt_hash")) != prompt:
            continue
        if _text(vp.get("related_entity_type")) != kind:
            continue
        if _text(vp.get("model_id")) != model or _text(vp.get("rule_pack_hash")) != rule_pack:
            continue
        rpid = _text(vp.get("related_proposal_id"))
        if not rpid:
            continue
        if not any(
            ptype == f"{kind}.proposed.v1" and pseq < vseq and plineage == lineage
            for pseq, ptype, plineage in proposed_by_id.get(rpid, [])
        ):
            continue
        outcome = _graded_outcome(vp, "llm_tier_outcome")
        # A verdict one commit used, or one an id already pairs to a commit that needs a verdict, is
        # that commit's: it cannot serve this one. A verdict that does NOT support a write still counts
        # against it, whoever else used it, so it can never be hidden.
        spent = vseq in taken or any(
            t not in COMMITTED_VERDICT_EXEMPT for t, _s in anchors.get(rpid, [])
        )
        if spent and _outcome_satisfies(outcome, has_approver=True, has_override=False):
            continue
        outcomes.append(outcome)
        if not spent:
            used.append(vseq)
    taken.update(used)
    # own = at least one matching verdict was free for this commit. A spent rejection only counts against a write.
    return outcomes, bool(used)


def check_verifier_verdict_presence(events: list[dict[str, Any]]) -> CheckResult:
    """For every *.committed.v1 event, assert a Verifier verdict (embedded in
    the event, or a standalone verifier.verdict.v1 paired to it) exists and
    records an approving outcome.

    Coverage is exhaustive + fail-closed: an unrecognised committed kind FAILs.
    A kind that gained its verdict field only later DEGRADES when a historical
    event carries none (rather than FAILing a legitimate old seal); a verdict
    that is present but rejected FAILs on every kind.
    """
    result = CheckResult(check="verifier_verdict_presence", status="PASS")
    _check_lifecycle_verdicts(events, result)

    verdicts: list[dict[str, Any]] = []
    committed: list[dict[str, Any]] = []
    unclassified: list[dict[str, Any]] = []
    proposed: list[dict[str, Any]] = []  # used to map proposal_id -> entity
    gated_exempt: dict[str, int] = {}
    unclassified_gated: list[dict[str, Any]] = []

    for ev in events:
        et = ev.get("event_type", "")
        if et in GATED_WRITE_VERDICT_EXEMPT:
            gated_exempt[et] = gated_exempt.get(et, 0) + 1
            if et in TRUST_PAGE_WRITE_EVENTS and _trust_write_carries_failed_verdict(_payload(ev)):
                _fail_committed(
                    result,
                    "trust_write_verdict_not_passed",
                    ev,
                    "a trust page write that carries a verifier verdict which did not pass; the write was "
                    "refused by the rule check and cannot stand as an approved act",
                )
        elif et in GATED_WRITE_OUTCOME_CHECKED:
            outcome = _payload(ev).get("verdict_outcome")
            if str(outcome or "").strip().upper() != "APPROVED":
                _fail_committed(
                    result,
                    "attestation_verdict_not_approved",
                    ev,
                    "an attestation whose carried verdict_outcome is missing or "
                    "not APPROVED; the attested grade does not support the "
                    "attestation",
                )
        elif _is_unclassified_gated_write(et, _payload(ev)):
            unclassified_gated.append(ev)
        if et == "verifier.verdict.v1":
            verdicts.append(ev)
        elif et in COMMITTED_EVENT_TYPES:
            committed.append(ev)
        elif et.endswith(".committed.v1"):
            # A committed kind this verifier does not classify. Fail closed: a
            # newly-shipped committed kind must be added to a set above (verdict
            # required / historical-optional / exempt) deliberately, never left
            # silently unchecked.
            unclassified.append(ev)
        elif et.endswith(".proposed.v1"):
            proposed.append(ev)

    # Verdict distribution.
    passed = 0
    rejected = 0
    for v in verdicts:
        payload = _payload(v)
        if payload.get("passed") is True:
            passed += 1
        else:
            rejected += 1
    result.count = len(verdicts)
    overrides, first_override_seq = _index_anchored_overrides(events)
    result.notes.append(
        f"{len(verdicts)} standalone verifier verdicts: "
        f"{passed} passed, {rejected} rejected/non-passed"
    )

    # Fail-closed: an unrecognised committed kind cannot be verified at all.
    for u in unclassified:
        _fail_committed(
            result,
            "committed_kind_unclassified",
            u,
            "a committed event of a kind this verifier does not classify; its "
            "Verifier verdict cannot be located, so the write is unverifiable - "
            "the verifier must be taught this kind before the bundle is trusted",
        )

    for u in unclassified_gated:
        _fail_committed(
            result,
            "gated_write_unclassified",
            u,
            "a write that carries an approval token and an approver, of a kind "
            "this verifier does not classify; whether it needed a Verifier "
            "verdict cannot be told, so the write is unverifiable - the "
            "verifier must be taught this kind before the bundle is trusted",
        )

    if gated_exempt:
        listing = ", ".join(f"{n} {k}" for k, n in sorted(gated_exempt.items()))
        result.notes.append(
            f"{sum(gated_exempt.values())} human-decision writes carry no model "
            f"verdict by design (the person is the decision; nothing to grade): "
            f"{listing}"
        )

    if not committed:
        if not unclassified:
            # Nothing to assert against. Surface as PASS with notes.
            result.notes.append(
                "no *.committed.v1 events in this bundle; nothing to pair"
            )
        return result

    # Build the proposal -> entity index from proposed events.
    proposal_to_entity: dict[str, tuple[str, str]] = {}
    for p in proposed:
        payload = _payload(p)
        # proposed events use proposal_id as entity_id in the wire
        # format; cross-reference by entity_id when present.
        eid = p.get("entity_id") or payload.get("proposal_id")
        if eid:
            proposal_to_entity[str(eid)] = (
                p.get("entity_type", ""),
                str(eid),
            )

    # Index verdicts by the proposal id they reference, carrying the OUTCOME
    # (not just a passed bool) so a human_review verdict a human then approved
    # is told apart from a rejection.
    verdict_index: dict[str, list[str]] = {}
    for v in verdicts:
        payload = _payload(v)
        rpid = payload.get("related_proposal_id")
        if rpid:
            verdict_index.setdefault(str(rpid), []).append(
                _standalone_verdict_outcome(payload)
            )

    # Indexes for the graded-content fallback (2.7.22).
    verdicts_by_cih: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for v in verdicts:
        vseq = _graded_seq(v)
        vcih = _text(_payload(v).get("canonical_inputs_hash"))
        if vseq is not None and vcih:
            verdicts_by_cih.setdefault(vcih, []).append((vseq, _payload(v)))
    proposed_by_id: dict[str, list[tuple[int, str, str]]] = {}
    for p in proposed:
        pseq = _graded_seq(p)
        pp = _payload(p)
        if pseq is None:
            continue
        for pid in {_text(pp.get("canonical_id")), _text(pp.get("proposal_id"))} - {""}:
            proposed_by_id.setdefault(pid, []).append(
                (pseq, str(p.get("event_type")), _text(pp.get("lineage_key")))
            )

    # For each committed event, look for a matching verdict via the
    # canonical entity_id ↔ proposal_id pairing OR via the payload's
    # approval_jti (which threads through approval.issued.v1 and the
    # verdict's related_proposal_id when available).
    embedded_ok = 0
    standalone_ok = 0
    graded_ok = 0
    graded_taken: set[int] = set()
    committed_anchors: dict[str, list[tuple[str, Optional[int]]]] = {}
    # A verdict is also consumed by any other event that names its draft by entity_id (the lifecycle rule
    # verdicts), so those spend it too.
    for ev in events:
        _et = str(ev.get("event_type"))
        if (
            _et == "verifier.verdict.v1" or _et.endswith(".proposed.v1") or _et in COMMITTED_EVENT_TYPES
            or _et in COMMITTED_VERDICT_EXEMPT or not ev.get("entity_id")
        ):
            continue
        committed_anchors.setdefault(str(ev.get("entity_id")), []).append((_et, _graded_seq(ev)))
    for c in committed:
        _pl = _payload(c)
        if c.get("event_type") in COMMITTED_VERDICT_EXEMPT or not isinstance(_pl, dict):
            continue  # an exempt event cannot consume a verdict; only a mapping holds ids
        for a in (_pl.get("proposal_id"), _pl.get("upstream_proposal_id"), c.get("entity_id")):
            if a:  # every id the id pairing reads (it stringifies), so a verdict it consumed is spent
                committed_anchors.setdefault(str(a), []).append((str(c.get("event_type")), _graded_seq(c)))
    # Claim graded-content verdicts in chain order for every commit, whichever way it is later accepted
    # (id pairing, embedded verdict or this fallback), so one verdict never serves two commits and the
    # outcome does not depend on the order of the file.
    graded_by_event: dict[int, tuple[list[str], bool]] = {}
    for ci in sorted(
        range(len(committed)),
        key=lambda i: (_graded_seq(committed[i]) is None, _graded_seq(committed[i]) or 0),
    ):
        c = committed[ci]
        if c.get("event_type") in GRADED_CONTENT_PAIRING_KINDS and isinstance(_payload(c), dict):
            graded_by_event[ci] = _graded_content_outcomes(
                c, _payload(c), verdicts_by_cih, proposed_by_id, graded_taken, committed_anchors
            )
    for ci, c in enumerate(committed):
        et = c.get("event_type")
        payload = _payload(c)

        # Rule-only / envelope kinds carry no model verdict by design; there is
        # nothing to pair and nothing missing.
        if et in COMMITTED_VERDICT_EXEMPT:
            continue

        # A PRESENT-but-MALFORMED verdict (empty object, array, scalar, boolean)
        # is garbage, not an absent optional field: it FAILs on every non-exempt
        # kind, evaluated BEFORE any embedded/standalone/legacy pairing so a
        # historical-optional kind can never DEGRADE past it, identically in the
        # JS twin. An absent/null field falls through to the bucket logic below.
        if _verdict_field_state(payload) == "malformed":
            _fail_committed(
                result,
                "committed_with_malformed_embedded_verdict",
                c,
                "the committed event carries a verifier_verdict field that is not "
                "a valid verdict object (empty object, array, or scalar value); a "
                "malformed verdict is not an absent one - fail closed",
            )
            continue

        # An embedded verdict satisfies presence on its own: it is inside this
        # very event, so it is covered by the same hash-chain integrity check
        # that already ran, and there is nothing to pair.
        if et in COMMITTED_EMBEDDED_REQUIRED:
            ev = _embedded_verdict(payload)
            if ev is None:
                result.status = "FAIL"
                result.anomalies.append({
                    "kind": "committed_without_embedded_verdict",
                    "event_id": c.get("event_id"),
                    "event_type": c.get("event_type"),
                    "message": (
                        "this kind carries its Verifier verdict INSIDE the "
                        "committed event (a required field of its canonical "
                        "schema) and the field is absent or malformed; "
                        "substrate Property #6 broken"
                    ),
                })
                continue
            if not _outcome_satisfies(
                _embedded_verdict_outcome(ev),
                has_approver=_committed_has_approver(payload),
                has_override=_committed_has_override(c, payload, overrides),
            ):
                if _rejected_only(
                    [_embedded_verdict_outcome(ev)]
                ) and _historical_inline_override(
                    c, payload, overrides, first_override_seq
                ):
                    _degrade_historical_override(result, c)
                    continue
                result.status = "FAIL"
                result.anomalies.append({
                    "kind": "committed_with_rejected_embedded_verdict",
                    "event_id": c.get("event_id"),
                    "event_type": c.get("event_type"),
                    "outcome": ev.get("outcome"),
                    "message": (
                        "the verdict embedded in this committed event does "
                        "not record an approving outcome and no human "
                        "approver or override recorded on the chain justifies the "
                        "write; an external write landed over a rejection"
                    ),
                })
                continue
            embedded_ok += 1
            continue

        # The historical-optional kinds (asset / risk / vendor / soa_decision)
        # may carry the verdict embedded - a later additive anchor the gateway
        # writes at grade time. Of the always-standalone kinds (internal_control /
        # policy / procedure) only a policy is also read from its own record
        # (M-152); controls and procedures still need the standalone
        # verifier.verdict.v1, which an embedded one must never stand in for.
        historical = et in COMMITTED_VERDICT_HISTORICAL_OPTIONAL
        # M-152 (Q-126): a policy commit also carries its Verifier verdict in its
        # own record; that in-record verdict is accepted for policies. A policy
        # with no verdict anywhere still FAILs (committed_without_verdict) and a
        # rejected one still needs its approver/override. Controls and
        # procedures are unchanged.
        embedded = (
            _embedded_verdict(payload)
            if historical or et == "policy.committed.v1"
            else None
        )
        if embedded is not None and not historical:
            # A policy's in-record verdict never hides a contradicting standalone
            # verdict: if standalone verdicts exist and none is acceptable, take
            # the standalone path below, which FAILs the write.
            _pol_ids = [
                str(a)
                for a in (
                    payload.get("proposal_id"),
                    payload.get("upstream_proposal_id"),
                    c.get("entity_id"),
                )
                if a
            ]
            _pol_outcomes = [o for a in _pol_ids for o in verdict_index.get(a, [])]
            if _pol_outcomes and not any(
                _outcome_satisfies(
                    o,
                    has_approver=_committed_has_approver(payload),
                    has_override=_committed_has_override(c, payload, overrides),
                )
                for o in _pol_outcomes
            ):
                embedded = None
            # A rejected verdict found by graded content (2.7.22) is never hidden by the in-record verdict:
            # every one allocated to this commit must support the write, else the commit fails here.
            _pol_graded = graded_by_event.get(ci, ([], False))[0] if embedded is not None else []
            if _pol_graded and not all(
                _outcome_satisfies(
                    o,
                    has_approver=_committed_has_approver(payload),
                    has_override=_committed_has_override(c, payload, overrides),
                )
                for o in _pol_graded
            ):
                _pol_failing = [
                    o for o in _pol_graded
                    if not _outcome_satisfies(
                        o,
                        has_approver=_committed_has_approver(payload),
                        has_override=_committed_has_override(c, payload, overrides),
                    )
                ]
                if _rejected_only(
                    _pol_failing + [_embedded_verdict_outcome(embedded)]
                ) and _historical_inline_override(c, payload, overrides, first_override_seq):
                    _degrade_historical_override(result, c)
                    continue
                _fail_committed(
                    result,
                    "committed_with_rejected_verdict_only",
                    c,
                    "a verdict graded on exactly what this commit sealed did not support the write, and no human "
                    "approver or override recorded on the chain justifies it; the verdict inside the record does "
                    "not hide it",
                    outcomes=sorted(set(_pol_graded)),
                )
                continue
        if embedded is not None:
            if not _outcome_satisfies(
                _embedded_verdict_outcome(embedded),
                has_approver=_committed_has_approver(payload),
                has_override=_committed_has_override(c, payload, overrides),
            ):
                if _rejected_only(
                    [_embedded_verdict_outcome(embedded)]
                ) and _historical_inline_override(
                    c, payload, overrides, first_override_seq
                ):
                    _degrade_historical_override(result, c)
                    continue
                _fail_committed(
                    result,
                    "committed_with_rejected_embedded_verdict",
                    c,
                    "the verdict embedded in this committed event records a "
                    "non-approving outcome and no human approver or override "
                    "recorded on the chain justifies the write",
                    outcome=embedded.get("outcome"),
                )
                continue
            embedded_ok += 1
            continue

        # No usable embedded verdict: pair a standalone verifier.verdict.v1. A
        # historical-optional kind that carries none DEGRADES (a legitimate
        # pre-field-era seal) rather than FAILing.
        # A committed record can be referenced by a verdict under any of the
        # ids it has worn. proposal_id is the single-commit case; but a batch
        # seal stamps the BATCH approval id as proposal_id while the graded
        # verdict references the entity's own canonical id (the refinement id
        # equals the canonical entity id), which is exactly this event's
        # entity_id. Pairing on proposal_id alone missed every batch-graded
        # record. Match on any of the three.
        anchor_ids = [
            str(a)
            for a in (
                payload.get("proposal_id"),
                payload.get("upstream_proposal_id"),
                c.get("entity_id"),
            )
            if a
        ]
        if not anchor_ids:
            # No id to pair a verdict on. For a kind that gained its verdict
            # field only later this is a legitimate pre-field seal -> DEGRADE;
            # for an always-graded kind it is an unverifiable write -> FAIL.
            if historical:
                _degrade_committed(
                    result,
                    c,
                    "carries no anchored Verifier verdict and no id to pair one. "
                    "Provenance uncertain: this kind's verdict field is still "
                    "schema-OPTIONAL, so this tool cannot determine whether this "
                    "record predates the verdict field or is a policy-violating "
                    "modern omission - reported DEGRADED, not failed, to avoid "
                    "failing a legitimate historical export. The write is not "
                    "independently attestable; strict failure of a modern "
                    "omission requires the schema to make the field required",
                )
            else:
                _fail_committed(
                    result,
                    "committed_no_proposal_anchor",
                    c,
                    "committed event carries no proposal_id, "
                    "upstream_proposal_id, or entity_id; cannot pair with a "
                    "Verifier verdict - the write is unverifiable",
                )
            continue
        outcomes: list[str] = []
        for a in anchor_ids:
            outcomes.extend(verdict_index.get(a, []))
        # Only when the ids pair nothing: find the verdict by what was graded (2.7.22). Every verdict
        # found this way must support the write, so a rejected one is never hidden by an approved one.
        graded = False
        if not outcomes and not historical:
            _g_outcomes, _g_own = graded_by_event.get(ci, ([], False))
            outcomes = list(_g_outcomes) if _g_own else []
            graded = bool(outcomes)
            embedded_graded = _embedded_verdict(payload)
            if graded and embedded_graded is not None:
                outcomes.append(_graded_outcome(embedded_graded, "outcome"))
        if not outcomes:
            if historical:
                _degrade_committed(
                    result,
                    c,
                    "carries no anchored Verifier verdict. Provenance uncertain: "
                    "this kind's verdict field is still schema-OPTIONAL, so this "
                    "tool cannot determine whether this record predates the "
                    "verdict field or is a policy-violating modern omission - "
                    "reported DEGRADED, not failed, to avoid failing a legitimate "
                    "historical export. The write is not independently "
                    "attestable; strict failure of a modern omission requires the "
                    "schema to make the field required",
                    anchor_ids=anchor_ids,
                )
            else:
                _fail_committed(
                    result,
                    "committed_without_verdict",
                    c,
                    "no verifier.verdict.v1 references any id this committed "
                    "event has worn - an external write landed without a "
                    "Verifier verdict in the chain",
                    proposal_id=anchor_ids[0],
                    anchor_ids=anchor_ids,
                )
            continue
        has_approver = _committed_has_approver(payload)
        has_override = _committed_has_override(c, payload, overrides)
        _quantifier = all if graded else any
        if not _quantifier(
            _outcome_satisfies(
                o, has_approver=has_approver, has_override=has_override
            )
            for o in outcomes
        ):
            # Every paired verdict is a rejection with no approver/override. A
            # present-but-rejected verdict is a real bypass on EVERY kind.
            if _rejected_only(outcomes) and _historical_inline_override(
                c, payload, overrides, first_override_seq
            ):
                _degrade_historical_override(result, c, proposal_id=anchor_ids[0])
                continue
            _fail_committed(
                result,
                "committed_with_rejected_verdict_only",
                c,
                "the Verifier rejected this proposal and no human approver or "
                "override recorded on the chain justifies the write; Verifier-bypass smell",
                proposal_id=anchor_ids[0],
                outcomes=sorted(set(outcomes)),
            )
            continue
        if graded:
            graded_ok += 1
            continue
        standalone_ok += 1

    # Say which mechanism carried the proof, so an auditor reading the report
    # can see all were checked rather than assuming a silent exemption.
    if embedded_ok or standalone_ok:
        result.notes.append(
            f"{embedded_ok} committed events carried an approving verdict "
            f"EMBEDDED in the event; {standalone_ok} paired an approving "
            f"standalone verifier.verdict.v1"
        )
    if graded_ok:
        result.notes.append(
            f"{graded_ok} committed event{'' if graded_ok == 1 else 's'} paired to "
            f"{'its' if graded_ok == 1 else 'their'} verifier verdict by graded content: the record was "
            f"refined after grading, so its ids no longer meet the verdict's, and the verdict was matched "
            f"on the inputs, prompt, model and rule pack the sealed commit records and on the record's lineage"
        )
    unanchored = sum(
        1 for a in result.anomalies
        if a.get("kind") == "committed_override_unanchored_historical"
    )
    if unanchored:
        result.notes.append(
            f"LIMITATION: {unanchored} record{'' if unanchored == 1 else 's'} sealed "
            "over a rejected Verifier verdict carry only an override flag inside "
            "the record and no override event on the chain (sealed before "
            "overrides were chain-anchored); reported DEGRADED, not accepted as "
            "proof."
        )
    historical_absent = sum(
        1 for a in result.anomalies
        if a.get("kind") == "committed_without_verdict_historical"
    )
    if historical_absent:
        result.notes.append(
            f"LIMITATION (provenance uncertain): {historical_absent} committed "
            f"events of kinds whose verdict field is still schema-OPTIONAL carry "
            f"no anchored verdict. This tool cannot determine whether they "
            f"predate the verdict field or are policy-violating modern omissions, "
            f"because the schema permits a verdict-less write; reported DEGRADED "
            f"(not failed) so legitimate historical exports still verify. Strict "
            f"failure of a modern omission requires the schema to make the field "
            f"required."
        )

    return result


def _payload(event: dict[str, Any]) -> dict[str, Any]:
    """Decode the base64'd canonical-JSON payload to a dict."""
    raw = event.get("payload") or ""
    if not raw:
        return {}
    try:
        decoded = base64.b64decode(raw)
        return json.loads(decoded)
    except Exception:  # noqa: BLE001
        return {}


# ---------------------------------------------------------------------------
# Check 4 - SoD (separation of duties)
# ---------------------------------------------------------------------------

# A tenant with more than one eligible reviewer may still let ONE person accept
# AND seal a routine record (evidence, a control test, a mapping) with a single
# click and no separate exception event, when the tenant's author-may-self-seal
# policy names that kind. The verifier confirms such a self-seal against the
# chain, not a self-attesting flag:
#   - the approval.approved.v1 payload's members[] each carry decision_basis
#     == "author_self_seal_record_kind" and an entity_kind, and
#   - every entity_kind is in the author-may-self-seal set resolved from the
#     LATEST tenant_policy.set.v1 for the policy key with sequence below the
#     approval's sequence, or, when no such event is on the chain, the
#     catalogue default embedded below (the same default the runtime applies
#     until per-tenant resolution is wired).
AUTHOR_SELF_SEAL_POLICY_KEY = "sod.author_self_seal_entity_types"

# CATALOGUE_DEFAULT_AUTHOR_SELF_SEAL mirrors the tenant-policy catalogue default
# for sod.author_self_seal_entity_types (the set the runtime applies when no
# tenant-set value is present). If that default changes, this constant and the
# verifier version move together.
CATALOGUE_V1_AUTHOR_SELF_SEAL = frozenset({
    "evidence",
    "control_test",
    "audit_finding",
    "audit_session",
    "asset",
    "vendor",
    "mapping",
    "link",
    # Saved answers and answer sets are record kinds the author seals alone.
    "claim",
    "questionnaire_response",
    # Who is asking, and the lens chosen to answer them.
    "obligation",
    "lens_decision",
    "lens_applicability",
    # A person acknowledging the company's own policy.
    "policy_acknowledgement",
    # The bounded population of a legacy export carried in.
    "migration_summary",
    # A risk register entry and a corrective action.
    "risk",
    "remediation",
})

# SOD_CATALOGUE_VERSION is the version of the author-self-seal default above. Version 1 is everything through 2.7.15.
# Version 2 (verifier 2.7.17) adds the five trust page kinds. A kind added later can only appear on a chain written
# after the product knew it, so an older chain has no approval of it and verifies the same under either version.
SOD_CATALOGUE_VERSION = 2


# SOD_CATALOGUE_VERSION is the newest version of the author-self-seal default. Version 1 is everything through 2.7.15.
# Version 2 (verifier 2.7.17) adds the five trust page kinds. An approval says which version it was sealed under
# (members carry sod_catalogue_version, written by the sealer); one that says nothing is read under version 1, so
# a trust page kind sealed by its author alone with no declared version FAILS (fail closed) and an older chain
# verifies exactly as before.
SOD_CATALOGUE_VERSION = 2
TRUST_PAGE_SELF_SEAL_KINDS = frozenset({"disclosure", "access_grant", "branding", "nda_text", "third_party_document"})
CATALOGUE_DEFAULT_AUTHOR_SELF_SEAL = CATALOGUE_V1_AUTHOR_SELF_SEAL | TRUST_PAGE_SELF_SEAL_KINDS  # version 2 (newest)
# The second-person floor (tenantpolicy secondPersonFloorKinds): refused at validation, so no tenant set can hold
# them. The offline check applies the floor too, so a set that does is read without them.
SECOND_PERSON_FLOOR_KINDS = frozenset({"policy", "soa_decision", "risk_acceptance", "page_disclosure"})


def _catalogue_default_for(payload: dict[str, Any]) -> frozenset[str]:
    """The catalogue default in force for an approval, by the version its members declare (default 1)."""
    version = 1
    for m in payload.get("members") or []:
        v = m.get("sod_catalogue_version") if isinstance(m, dict) else None
        if isinstance(v, int) and not isinstance(v, bool) and v >= 2:
            version = 2
    return CATALOGUE_DEFAULT_AUTHOR_SELF_SEAL if version >= 2 else CATALOGUE_V1_AUTHOR_SELF_SEAL

DECISION_BASIS_SEALED_BY_OTHER = "sealed_by_other"
DECISION_BASIS_AUTHOR_SELF_SEAL_SOLE_SEALER = "author_self_seal_sole_sealer"
DECISION_BASIS_AUTHOR_SELF_SEAL_RECORD_KIND = "author_self_seal_record_kind"

TENANT_POLICY_SET_EVENT_TYPE = "tenant_policy.set.v1"


def _author_self_seal_set_at(
    policy_sets: list[dict[str, Any]], approval_seq: int, payload: Optional[dict[str, Any]] = None
) -> tuple[frozenset[str], str]:
    """Resolve the author-may-self-seal kind set in force for an approval.

    policy_sets is every tenant_policy.set.v1 event on the chain for the
    author-self-seal key, each a dict {"seq": int, "value": [kinds...]}. The
    governing value is the one from the LATEST such event with seq below the
    approval's seq (a policy must be set BEFORE the approval it governs). When
    none exists, the embedded catalogue default governs, matching the value the
    runtime applies when no tenant-set value is present.

    Returns (set, source) where source is the tenant_policy.set.v1 event_id
    that set it, or "catalogue_default".
    """
    best: dict[str, Any] | None = None
    for ps in policy_sets:
        seq = ps.get("seq")
        if seq is None or seq >= approval_seq:
            continue
        if best is None or seq > best["seq"]:
            best = ps
    if best is None:
        return _catalogue_default_for(payload or {}) - SECOND_PERSON_FLOOR_KINDS, "catalogue_default"
    kinds = {
        str(k).strip().lower()
        for k in (best.get("value") or [])
        if str(k).strip()
    }
    return frozenset(kinds) - SECOND_PERSON_FLOOR_KINDS, str(best.get("event_id") or "tenant_policy.set.v1")


def _record_kind_self_seal_ok(
    payload: dict[str, Any], resolved_set: frozenset[str]
) -> tuple[bool, str]:
    """Report whether a proposer==approver approval is a valid record-kind
    self-seal: members[] is present and non-empty, EVERY member's
    decision_basis is author_self_seal_record_kind, and EVERY member's
    entity_kind is in resolved_set. Returns (ok, reason); reason names the
    first disqualifier when not ok, or the human note when ok.
    """
    members = payload.get("members")
    if not isinstance(members, list) or not members:
        return False, "no members[] disclosure on the approval event"
    offending_kinds: list[str] = []
    for m in members:
        if not isinstance(m, dict):
            return False, "malformed member entry"
        if m.get("decision_basis") != DECISION_BASIS_AUTHOR_SELF_SEAL_RECORD_KIND:
            return False, (
                "a member's decision_basis is "
                f"{m.get('decision_basis')!r}, not "
                f"{DECISION_BASIS_AUTHOR_SELF_SEAL_RECORD_KIND!r}"
            )
        kind = str(m.get("entity_kind") or "").strip().lower()
        if not kind:
            return False, "a member has no entity_kind"
        if kind not in resolved_set:
            offending_kinds.append(kind)
    if offending_kinds:
        return False, (
            "entity kind(s) "
            + ", ".join(sorted(set(offending_kinds)))
            + " are not in the author-may-self-seal set for this tenant"
        )
    return True, (
        "every member is an author-self-sealable record kind"
    )


ADMIN_ROLE_NAME = "tenant-admin"


def _parse_ts(raw: Any) -> Optional[datetime]:
    """Parse an RFC3339 timestamp (any fractional digits) to an aware UTC time."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _active_admins_at(
    role_events: list[tuple[int, str, dict[str, Any]]],
    approval_seq: int,
    approval_time: Optional[datetime] = None,
) -> set[str]:
    """The subjects holding an active tenant-admin role as of an approval.

    Replays actor.role_assigned / role_revoked / person_departed events with a
    chain sequence BELOW the approval's, in sequence order, then keeps the roles
    whose effective interval covers the approval's time: a grant effective
    later, an expired grant, or a revocation that takes effect later is read as
    the membership counter reads it. An admin added or removed after the
    approval does not change who was admin when it happened. When the approval
    carries no readable time, only the sequence order is applied.
    """
    # (subject, role) -> every grant's [effective_from, effective_until]. A later
    # grant adds an interval; it never replaces an earlier one that is still
    # active. A revocation or departure only ever SHORTENS an interval.
    held: dict[tuple[str, str], list[list[Optional[datetime]]]] = {}
    ended = datetime.min.replace(tzinfo=timezone.utc)

    def _shorten(intervals: list[list[Optional[datetime]]], at: datetime) -> None:
        for iv in intervals:
            iv[1] = at if iv[1] is None else min(iv[1], at)

    for seq, et, p in sorted(role_events, key=lambda t: t[0]):
        if seq >= approval_seq:
            break
        sub = p.get("person_oidc_sub")
        if not isinstance(sub, str) or not sub:
            continue
        if et == "actor.role_assigned.v1":
            role = p.get("role_name")
            if isinstance(role, str) and role:
                start = _parse_ts(p.get("effective_from"))
                intervals = held.setdefault((sub, role), [])
                # The same grant re-recorded (same effective_from) replaces
                # itself; a different effective_from is another grant.
                intervals[:] = [iv for iv in intervals if iv[0] != start]
                intervals.append([start, _parse_ts(p.get("effective_until"))])
        elif et == "actor.role_revoked.v1":
            _shorten(
                held.get((sub, str(p.get("role_name") or "")), []),
                _parse_ts(p.get("effective_until")) or ended,
            )
        elif et == "actor.person_departed.v1":
            # The membership counter excludes a member whose departure is
            # recorded at once, whatever departed_at says, so a departure ends
            # every role held so far; it is never read as a future end.
            for key, intervals in held.items():
                if key[0] == sub:
                    _shorten(intervals, ended)
    admins: set[str] = set()
    for (sub, role), intervals in held.items():
        if role != ADMIN_ROLE_NAME:
            continue
        for start, until in intervals:
            if approval_time is not None:
                if start is not None and start > approval_time:
                    continue
                if until is not None and until <= approval_time:
                    continue
            elif until is not None and until == ended:
                continue
            admins.add(sub)
            break
    return admins


def _valid_sole_admin_exception(
    exc: dict[str, Any] | None, proposer: str, approver: str
) -> bool:
    """A self-approval is a DISCLOSED, valid state (not an SoD breach) when a
    matching sod_exception.recorded.v1 is anchored on the same chain: the
    documented sole-admin exception (kind sole_admin_self_approval) for this
    same self-approving subject. The product deliberately allows this for
    single-admin (e.g. Solo-tier) tenants and records the exception; the
    offline verifier must honour it or every Solo-tier bundle FAILs the "verify
    it yourself" tool.

    The count the exception states about itself is a claim, not proof:
    check_sod also recomputes the active-admin set from the chain's role events
    and requires it to be exactly the approver.
    """
    if not exc:
        return False
    if exc.get("kind") != "sole_admin_self_approval":
        return False
    # active_tenant_admin_count is a JSON number (int); the sole-admin
    # exception is valid ONLY at N==1. A multi-admin "exception" is not one.
    if exc.get("active_tenant_admin_count") != 1:
        return False
    # The exception must document THIS self-approval's subject on both sides.
    if (exc.get("proposer_subject") or "") != proposer:
        return False
    if (exc.get("approver_subject") or "") != approver:
        return False
    return True


def _canon_json(v: Any) -> Any:
    """Canonical JSON form shared with verify.mjs: integral floats read as ints
    (JS has one number type) and object keys sort at every depth."""
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, dict):
        return {str(k): _canon_json(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_canon_json(x) for x in v]
    return v


def _id_key(jti: Any) -> str:
    """Tally key for an approval id. A string and a malformed id never share a
    key ("s:" vs "j:" prefix), so the number 1 and the string "1" stay two ids;
    a malformed id is keyed by canonical JSON, so it is counted once and never
    raises."""
    if isinstance(jti, str):
        return "s:" + jti
    return "j:" + json.dumps(_canon_json(jti), sort_keys=True, separators=(",", ":"), default=str)


def check_sod(events: list[dict[str, Any]]) -> CheckResult:
    """For every approval.issued.v1 -> approval.approved.v1 pair,
    assert that proposer_subject != approver_subject.

    A self-approval FAILs UNLESS a matching sod_exception.recorded.v1 discloses
    a valid sole-admin exception (active_tenant_admin_count==1), in which case it
    is a disclosed, valid state (PASS with a note) - the single-admin SoD model
    the product deliberately allows. Rejected + expired approvals are not
    SoD-relevant (they didn't actually approve a write) so they aren't treated as
    anomalies, but the approval rate is reported.
    """
    result = CheckResult(check="sod_separation_of_duties", status="PASS")
    issued: dict[str, dict[str, Any]] = {}
    # approved keeps each approval.approved.v1 payload with its chain
    # sequence_number, needed to resolve the author-may-self-seal set in force
    # at that point for the record-kind self-seal check.
    approved: list[tuple[dict[str, Any], int, Optional[datetime]]] = []
    # sod_exceptions maps approval_jti -> the anchored sod_exception.recorded.v1
    # payload, so a self-approval can be checked against its disclosed exception.
    sod_exceptions: dict[str, dict[str, Any]] = {}
    # policy_sets collects every tenant_policy.set.v1 for the author-self-seal
    # key with its sequence + value, so a self-seal is resolved against the set
    # in force at the approval's sequence (not a claim on the approval event).
    policy_sets: list[dict[str, Any]] = []
    # role_events feeds the active-admin recompute for the sole-admin exception.
    role_events: list[tuple[int, str, dict[str, Any]]] = []
    unverifiable_count_jtis: list[str] = []
    dual_controlled_count = 0
    disclosed_exception_count = 0
    disclosed_jtis: list[str] = []
    # Self-approval notes count distinct approval ids, not events: an
    # approval id can carry several approved events.
    disclosed_keys: set[str] = set()
    record_self_seal_keys: set[str] = set()
    record_self_seal_count = 0
    record_self_seal_jtis: list[str] = []
    # Rejected and expired are kept as sets of approval ids, like the issued
    # map, so every figure in the summary line has ONE denominator: distinct
    # approval ids. Raw event counters made the four numbers incomparable.
    rejected_ids: set[str] = set()
    expired_ids: set[str] = set()
    # A batch approval is issued by approval.batch.issued.v1. It counts as an
    # issuance in the note; it is kept apart from `issued` so the
    # proposer fallback below reads exactly what it read before.
    batch_issued: set[str] = set()
    issued_id_keys: set[str] = set()
    for ev in events:
        et = ev.get("event_type", "")
        payload = _payload(ev)
        if et in (
            "actor.role_assigned.v1",
            "actor.role_revoked.v1",
            "actor.person_departed.v1",
        ):
            role_events.append((_event_seq(ev), et, payload))
            continue
        if et == TENANT_POLICY_SET_EVENT_TYPE:
            # Collected regardless of approval_jti: tenant_policy.set.v1 carries
            # the policy state, not an approval. Only the author-self-seal key
            # matters here.
            if payload.get("policy_key") == AUTHOR_SELF_SEAL_POLICY_KEY:
                try:
                    seq = int(ev.get("sequence_number", 0))
                except (TypeError, ValueError):
                    seq = 0
                policy_sets.append({
                    "seq": seq,
                    "value": payload.get("policy_value"),
                    "event_id": ev.get("event_id"),
                })
            continue
        jti = payload.get("approval_jti")
        if not jti:
            continue
        if et == "approval.issued.v1":
            issued_id_keys.add(_id_key(jti))
            issued[jti] = payload
        elif et == "approval.batch.issued.v1":
            batch_issued.add(jti)
        elif et == "approval.approved.v1":
            try:
                seq = int(ev.get("sequence_number", 0))
            except (TypeError, ValueError):
                seq = 0
            approved.append((
                payload,
                seq,
                _parse_ts(payload.get("approved_at")) or _parse_ts(ev.get("valid_time")),
            ))
        elif et == "sod_exception.recorded.v1":
            sod_exceptions[jti] = payload
        elif et in ("approval.rejected.v1", "approval.member.rejected.v1"):
            # A person rejecting one item of a request (member) and rejecting
            # the whole request both count as a rejection of that approval id
            #. Count only: no verdict reads this set.
            rejected_ids.add(_id_key(jti))
        elif et == "approval.expired.v1":
            expired_ids.add(_id_key(jti))

    result.count = len(approved)
    issued_ids = issued_id_keys | {_id_key(j) for j in batch_issued}
    approved_ids = {_id_key(a.get("approval_jti")) for a, _seq, _time in approved}
    n_issued = len(issued_ids)
    # The four tallies are different outcomes over distinct approval ids, not a
    # breakdown of the issued figure: an approval can carry several
    # events, and an id can appear with no issuance event in this bundle.
    result.notes.append(
        "Counted by approval id, each id once per outcome: "
        f"{n_issued} approval{'' if n_issued == 1 else 's'} issued, "
        f"{len(approved_ids)} approved, "
        f"{len(rejected_ids)} rejected, {len(expired_ids)} expired. "
        "These are separate tallies, not parts of one total."
    )
    if len(approved) != len(approved_ids):
        result.notes.append(
            f"{len(approved)} approved events were recorded for "
            f"{len(approved_ids)} approval id{'' if len(approved_ids) == 1 else 's'}."
        )
    approved_unissued = len(approved_ids - issued_ids)
    if approved_unissued:
        result.notes.append(
            f"FINDING: {approved_unissued} of the {len(approved_ids)} approved "
            f"id{'' if len(approved_ids) == 1 else 's'} "
            f"{'has' if approved_unissued == 1 else 'have'} no issuance event in "
            "this bundle (neither approval.issued.v1 nor "
            "approval.batch.issued.v1), so who issued "
            f"{'it' if approved_unissued == 1 else 'them'} and when is not "
            "shown here. Each is still checked below from its own approved event."
        )
    expired_unissued = len(expired_ids - issued_ids)
    if expired_unissued:
        if expired_unissued == 1:
            tail = (f"{expired_unissued} of the {len(expired_ids)} expired "
                    f"id{'' if len(expired_ids) == 1 else 's'} has no issuance "
                    "event in this bundle.")
        else:
            tail = (f"{expired_unissued} of the {len(expired_ids)} expired ids "
                    "have no issuance event in this bundle.")
        result.notes.append("FINDING: " + tail)

    for a, approval_seq, approval_time in approved:
        jti = a.get("approval_jti")
        proposer = a.get("proposer_subject") or ""
        approver = a.get("approved_by_subject") or ""
        if not proposer:
            # Fall back to the issued event's proposer.
            issued_payload = issued.get(jti, {})
            proposer = issued_payload.get("proposer_subject") or ""
        if not proposer or not approver:
            result.anomalies.append({
                "kind": "sod_subject_missing",
                "approval_jti": jti,
                "message": (
                    "approval.approved.v1 missing proposer_subject or "
                    "approved_by_subject; cannot perform SoD check"
                ),
            })
            continue
        if proposer != approver:
            dual_controlled_count += 1
        if proposer == approver:
            exc = sod_exceptions.get(jti)
            sole_admin_ok = _valid_sole_admin_exception(exc, proposer, approver)
            if sole_admin_ok and any(
                et == "actor.role_assigned.v1" for _s, et, _p in role_events
            ):
                # Recompute who was admin at this approval from the chain's own
                # role events; the exception's stated count is not trusted.
                sole_admin_ok = _active_admins_at(
                    role_events, approval_seq, approval_time
                ) == {approver}
            elif sole_admin_ok:
                # The bundle carries no role events, so the stated count cannot
                # be checked. Surface that instead of passing it silently, and
                # keep it out of the validated count and its note.
                unverifiable_count_jtis.append(str(jti))
                continue
            if sole_admin_ok:
                # DISCLOSED sole-admin self-approval: the product allows a
                # single tenant-admin to self-approve and anchors the exception
                # on the same chain. This is a valid, transparent state, not a
                # breach - record a note and do NOT fail.
                # Counted, not narrated. One note PER approval rendered
                # hundreds of identical sentences on a real estate, differing
                # only by an id and saying nothing the summary does not. The
                # summary below carries the count, the meaning, and every id.
                if _id_key(jti) not in disclosed_keys:
                    disclosed_keys.add(_id_key(jti))
                    disclosed_exception_count += 1
                    disclosed_jtis.append(str(jti))
                continue
            # Record-kind self-seal: a tenant with a second eligible reviewer
            # may still let ONE person accept AND seal a routine record with a
            # single click and no exception event. It is valid, not a breach,
            # when EVERY member of the approval discloses decision_basis ==
            # author_self_seal_record_kind AND every entity_kind is in the
            # author-may-self-seal set resolved from the chain (latest
            # tenant_policy.set.v1 before the approval's sequence, else the
            # catalogue default). The set is resolved from the chain, never
            # trusted from a claim on the approval event.
            resolved_set, _src = _author_self_seal_set_at(policy_sets, approval_seq, a)
            ok, _reason = _record_kind_self_seal_ok(a, resolved_set)
            if ok:
                if _id_key(jti) not in record_self_seal_keys:
                    record_self_seal_keys.add(_id_key(jti))
                    record_self_seal_count += 1
                    record_self_seal_jtis.append(str(jti))
                continue
            # Genuine SoD breach: proposer==approver with no valid disclosed
            # exception (no exception event, wrong kind, or more than one active
            # admin) AND not a valid record-kind self-seal (a governance kind, a
            # missing or wrong members disclosure, or a kind outside the
            # resolved set).
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "self_approval",
                "approval_jti": jti,
                "proposer_subject": proposer,
                "approver_subject": approver,
                "message": (
                    "proposer and approver are the same OIDC subject with no "
                    "disclosed sole-admin exception and no valid record-kind "
                    f"self-seal ({_reason}); separation-of-duties breached - "
                    "the same human drafted AND approved this write"
                ),
            })

    if record_self_seal_count:
        note = (
            f"{record_self_seal_count} self-approval"
            f"{'' if record_self_seal_count == 1 else 's'} validated as a "
            "record-kind self-seal: the author accepted AND sealed a routine "
            "record kind (for example evidence, a control test, or a mapping) "
            "that this tenant's author-may-self-seal policy, resolved from the "
            "chain, lets one person seal, so no second reviewer was required "
            "and no exception event was needed."
        )
        if record_self_seal_jtis:
            note += " Approvals: " + ", ".join(record_self_seal_jtis)
        result.notes.append(note)

    if disclosed_exception_count:
        note = (
            f"{disclosed_exception_count} self-approval"
            f"{'' if disclosed_exception_count == 1 else 's'} validated by a "
            "disclosed sole-admin exception recorded on this chain "
            "(sod_exception.recorded.v1): the tenant's role events show exactly "
            "one active administrator at the time, so proposer and approver are "
            "necessarily the same person, and the exception says so on the "
            "record."
        )
        if disclosed_jtis:
            note += " Approvals: " + ", ".join(disclosed_jtis)
        result.notes.append(note)

    if unverifiable_count_jtis:
        if result.status != "FAIL":
            result.status = "DEGRADED"
        result.anomalies.append({
            "kind": "sole_admin_count_unverifiable",
            "approval_jtis": unverifiable_count_jtis,
            "message": (
                f"{len(unverifiable_count_jtis)} sole-admin exception"
                f"{'' if len(unverifiable_count_jtis) == 1 else 's'} could not be "
                "checked: this bundle carries no actor.role_assigned.v1 events, "
                "so the number of active administrators cannot be recomputed. "
                "The exception's own stated count is not accepted as proof."
            ),
        })

    result.details = {
        "author_sealed_under_policy": record_self_seal_count,
        "sole_admin_exceptions": disclosed_exception_count,
        "dual_controlled": dual_controlled_count,
    }
    result.notes.append(
        "Approvals by who made them: "
        f"{record_self_seal_count} author-sealed under policy; "
        f"{disclosed_exception_count} sole-admin "
        f"self-approval{'' if disclosed_exception_count == 1 else 's'}; "
        f"{dual_controlled_count} dual-controlled (a second person approved)."
    )
    return result


# ---------------------------------------------------------------------------
# Check 4b - Two-act oversight (accept, then a second person seals)
# ---------------------------------------------------------------------------
#
# Some tenants keep two people on their governance documents: one drafts (with
# the help of their AI) and accepts the draft, a second person seals it. On the
# chain this is a two-step trail:
#   - approval.accepted.v1 records that the author looked at the work and parked
#     it. Its members[] each carry a decision: `accepted` (a governance record
#     parked for a second person) or `sealed` (a routine record kind the author
#     sealed there and then, which needs no second person).
#   - approval.approved.v1 (emitted later, when the second person seals) carries
#     the sealer as approved_by_subject and lists the same member proposal ids.
#
# This check confirms the oversight actually happened where the tenant asked for
# it: every GOVERNANCE record the author only ACCEPTED must be sealed by a
# DIFFERENT subject. A record kind the author sealed with one click is never
# required to show a second person - the whole point of the record/governance
# split is that routine records do not need one. An accepted record with no seal
# yet is reported as "awaiting confirmation", which is a normal in-flight state,
# not an anomaly. The record/governance split is resolved from the chain the
# same way the separation-of-duties check resolves it (the latest
# tenant_policy.set.v1 for the author-may-self-seal key before the acceptance, or
# the catalogue default embedded above when none is set).

TWO_ACT_ACCEPTED_EVENT_TYPE = "approval.accepted.v1"
ACCEPTED_DECISION_ACCEPTED = "accepted"


def _approved_by_member_proposal(
    events: list[dict[str, Any]],
) -> dict[str, list[tuple[str, int]]]:
    """Index every approval.approved.v1 by the proposal id of each member it
    sealed. Returns proposal_id -> [(approved_by_subject, sequence_number), ...].

    A seal of a two-act batch names the batch member ids in members[]; the
    top-level proposal_id of that event is the job id, not the member id, so the
    correlation to an accepted member is always through members[].proposal_id.
    A single-member approval with no members[] disclosure falls back to the
    top-level proposal_id so an older single-entity shape still correlates.
    """
    by_proposal: dict[str, list[tuple[str, int]]] = {}
    for ev in events:
        if ev.get("event_type") != "approval.approved.v1":
            continue
        payload = _payload(ev)
        approved_by = payload.get("approved_by_subject") or ""
        try:
            seq = int(ev.get("sequence_number", 0))
        except (TypeError, ValueError):
            seq = 0
        members = payload.get("members")
        seen_pid = False
        if isinstance(members, list):
            for m in members:
                if not isinstance(m, dict):
                    continue
                pid = str(m.get("proposal_id") or "").strip()
                if pid:
                    by_proposal.setdefault(pid, []).append((approved_by, seq))
                    seen_pid = True
        if not seen_pid:
            pid = str(payload.get("proposal_id") or "").strip()
            if pid:
                by_proposal.setdefault(pid, []).append((approved_by, seq))
    return by_proposal


def check_two_act(events: list[dict[str, Any]]) -> CheckResult:
    """For every governance-kind member the author only ACCEPTED (parked for a
    second person), assert a later approval.approved.v1 for that member's
    proposal id records a DIFFERENT subject as the sealer.

    A record kind the author sealed with one click needs no second person, so it
    is never required to show one. An accepted member with no seal yet is
    reported as awaiting confirmation, not an anomaly. The record/governance
    split is resolved from the chain (the latest tenant_policy.set.v1 for the
    author-may-self-seal key before the acceptance, else the catalogue default),
    which is the basis reported in the note.
    """
    result = CheckResult(check="two_act_oversight", status="PASS")
    approved_by_proposal = _approved_by_member_proposal(events)
    policy_sets: list[dict[str, Any]] = []
    for ev in events:
        if ev.get("event_type") != TENANT_POLICY_SET_EVENT_TYPE:
            continue
        payload = _payload(ev)
        if payload.get("policy_key") != AUTHOR_SELF_SEAL_POLICY_KEY:
            continue
        try:
            seq = int(ev.get("sequence_number", 0))
        except (TypeError, ValueError):
            seq = 0
        policy_sets.append({
            "seq": seq,
            "value": payload.get("policy_value"),
            "event_id": ev.get("event_id"),
        })

    accepted_governance = 0
    sealed_by_second = 0
    awaiting = 0
    catalogue_resolved = 0
    policy_resolved = 0
    for ev in events:
        if ev.get("event_type") != TWO_ACT_ACCEPTED_EVENT_TYPE:
            continue
        payload = _payload(ev)
        try:
            accepted_seq = int(ev.get("sequence_number", 0))
        except (TypeError, ValueError):
            accepted_seq = 0
        accepted_by = payload.get("accepted_by_subject") or ""
        jti = payload.get("approval_jti") or ""
        resolved_set, src = _author_self_seal_set_at(policy_sets, accepted_seq, payload)
        members = payload.get("members")
        if not isinstance(members, list):
            continue
        for m in members:
            if not isinstance(m, dict):
                continue
            if m.get("decision") != ACCEPTED_DECISION_ACCEPTED:
                # `sealed` members were sealed at act 1 (a routine record kind, or
                # a sole-sealer governance carve-out the SoD check validates); the
                # two-act oversight requirement does not apply to them.
                continue
            kind = str(m.get("entity_kind") or "").strip().lower()
            # A parked member is a governance kind by construction (record kinds
            # seal at act 1). Resolve it against the chain anyway so the note
            # states the basis, and so a record kind that somehow parked is not
            # held to the second-person rule the split says it is exempt from.
            if kind and kind in resolved_set:
                continue
            accepted_governance += 1
            if src == "catalogue_default":
                catalogue_resolved += 1
            else:
                policy_resolved += 1
            pid = str(m.get("proposal_id") or "").strip()
            seals = [
                (who, s)
                for (who, s) in approved_by_proposal.get(pid, [])
                if s > accepted_seq
            ]
            if not seals:
                awaiting += 1
                continue
            seals.sort(key=lambda ws: ws[1])
            sealer = seals[0][0]
            if sealer and accepted_by and sealer != accepted_by:
                sealed_by_second += 1
            else:
                result.status = "FAIL"
                result.anomalies.append({
                    "kind": "two_act_self_seal",
                    "approval_jti": jti,
                    "proposal_id": pid,
                    "entity_kind": kind,
                    "accepted_by_subject": accepted_by,
                    "sealed_by_subject": sealer,
                    "message": (
                        "a governance record was accepted AND sealed by the same "
                        f"OIDC subject ({accepted_by or 'unknown'}); the tenant "
                        "keeps a second person on this kind, so a different "
                        "reviewer had to seal what the author accepted - the "
                        "two-act oversight was not satisfied"
                    ),
                })

    result.count = accepted_governance
    if accepted_governance == 0:
        result.notes.append(
            "no governance records were parked for a second person in this "
            "bundle; nothing to check"
        )
        return result

    basis = []
    if catalogue_resolved:
        basis.append(
            f"{catalogue_resolved} resolved against the catalogue-default "
            "author-may-self-seal set"
        )
    if policy_resolved:
        basis.append(
            f"{policy_resolved} resolved against a tenant policy set on the chain"
        )
    result.notes.append(
        f"{accepted_governance} governance record"
        f"{'' if accepted_governance == 1 else 's'} were accepted by their "
        "author and required a second person to seal "
        f"({'; '.join(basis)})."
    )
    if sealed_by_second:
        result.notes.append(
            f"{sealed_by_second} were sealed by a different reviewer than the "
            "person who accepted them - two-act oversight complete."
        )
    if awaiting:
        result.notes.append(
            f"{awaiting} accepted and awaiting a second reviewer's seal; this is "
            "a normal in-flight state, not an anomaly."
        )
    return result


# ---------------------------------------------------------------------------
# Check - per-member attestation (the recorded-click regime)
# ---------------------------------------------------------------------------


def _attestation_ok(member: dict[str, Any]) -> bool:
    """An attestation is present and non-empty: a `by` and non-blank `text`."""
    att = member.get("attestation")
    if not isinstance(att, dict):
        return False
    return bool(str(att.get("by") or "").strip()) and bool(
        str(att.get("text") or "").strip()
    )


def check_member_attestation(events: list[dict[str, Any]]) -> CheckResult:
    """Every member of an approval produced under the recorded-click regime must
    carry a non-empty attestation: the person and the words they recorded when
    they ticked that item.

    Gated on the approval's own attestation_required flag, which lives in the
    hashed payload, so it is tamper-evident: an approval that predates the regime
    (flag absent) is not asked for attestations and passes unchanged, so older
    exports verify byte-identically on this verifier. When the flag is set, a
    member missing its attestation is a failure: the chain would otherwise not
    prove the person recorded a click for that item before it sealed.
    """
    result = CheckResult(check="member_attestation", status="PASS")
    gated = [
        e
        for e in events
        if e.get("event_type") == "approval.approved.v1"
        and _payload(e).get("attestation_required") is True
    ]
    result.count = len(gated)
    if not gated:
        result.notes.append(
            "no recorded-click approvals in this bundle; nothing to verify"
        )
        return result

    # M-152 (Q-127): a member whose write was refused has a recorded
    # canonical.write.failed.v1 for that approval and proposal; nothing was
    # sealed for it, so there is no click to attest. Only that exact
    # (approval_jti, proposal_id) pair is skipped.
    refused: set[tuple[str, str]] = set()
    for e in events:
        if e.get("event_type") == "canonical.write.failed.v1":
            fp = _payload(e)
            if fp.get("approval_jti") and fp.get("proposal_id"):
                refused.add((str(fp["approval_jti"]), str(fp["proposal_id"])))

    refused_skipped = 0
    for ev in gated:
        payload = _payload(ev)
        members = payload.get("members")
        if not isinstance(members, list) or not members:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "attestation_members_missing",
                "event_id": ev.get("event_id"),
                "approval_jti": payload.get("approval_jti"),
                "message": (
                    "approval declares a recorded click but lists no members "
                    "to carry the attestation"
                ),
            })
            continue
        for m in members:
            if (
                isinstance(m, dict)
                and (str(payload.get("approval_jti")), str(m.get("proposal_id")))
                in refused
            ):
                refused_skipped += 1
                continue
            if not isinstance(m, dict) or not _attestation_ok(m):
                result.status = "FAIL"
                result.anomalies.append({
                    "kind": "member_attestation_missing",
                    "event_id": ev.get("event_id"),
                    "approval_jti": payload.get("approval_jti"),
                    "proposal_id": (
                        m.get("proposal_id") if isinstance(m, dict) else None
                    ),
                    "entity_kind": (
                        m.get("entity_kind") if isinstance(m, dict) else None
                    ),
                    "message": (
                        "a member of a recorded-click approval has no recorded "
                        "attestation; the chain cannot prove the person ticked "
                        "and approved this item"
                    ),
                })

    if result.status == "PASS":
        result.notes.append(
            f"verified a recorded attestation on every member of {len(gated)} "
            "recorded-click approvals"
            + (f" ({refused_skipped} refused members skipped: no write was sealed)"
               if refused_skipped else "")
        )
    return result


# ---------------------------------------------------------------------------
# Check 5 - Skill provenance
# ---------------------------------------------------------------------------


SKILL_ACTIVATION_EVENT_TYPE = "skill.activated.v1"
KNOWN_DEGRADED_SIGNING_IDENTITY = "build-time-yaml-loader@kanonik.ai"


def load_skill_signing_keys(override_path: Optional[Path] = None) -> list[dict[str, Any]]:
    """Load the pinned first-party skill-signing public keys (ECDSA P-256) from
    the key list built into this file (`skill_signing_keys`), plus an optional
    override file of the same shape. Best-effort: a missing or unreadable
    source contributes nothing. Each entry is {signing_key_id, label, pem(bytes)}.
    """
    keys: list[dict[str, Any]] = []
    docs: list[Any] = [SHIPPED_TRUSTED_KEYS_DOC]
    if override_path is not None:
        try:
            if override_path.exists():
                docs.append(json.loads(override_path.read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            pass
    for doc in docs:
        for k in (doc.get("skill_signing_keys") or []) if isinstance(doc, dict) else []:
            pem = _coerce_pem(k.get("pem")) if isinstance(k, dict) else None
            if pem is not None:
                keys.append({
                    "signing_key_id": k.get("signing_key_id") or "",
                    "label": k.get("label") or "",
                    "pem": pem,
                })
    return keys


class _CryptoUnavailable(Exception):
    """The optional `cryptography` library is not installed."""


def _verify_skill_signature(
    manifest_hash: str,
    signature_b64: str,
    skill_keys: list[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """Return the pinned skill-signing key whose ECDSA-P256 signature this is
    over the digest `manifest_hash` names ("sha256:<hex>"), or None. The signer
    signed the SHA-256 of manifest.yaml, so the digest alone verifies it; the
    manifest itself is not needed."""
    try:
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric.utils import (  # noqa: PLC0415
            Prehashed,
        )
        from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
            load_pem_public_key,
        )
    except ImportError:
        raise _CryptoUnavailable() from None
    if not (manifest_hash.startswith("sha256:") and len(manifest_hash) == 71):
        return None
    try:
        digest = bytes.fromhex(manifest_hash[len("sha256:"):])
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:  # noqa: BLE001
        return None
    for k in skill_keys:
        pem = _coerce_pem(k.get("pem"))
        if pem is None:
            continue
        try:
            pub = load_pem_public_key(pem)
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                continue
            pub.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
            return k
        except Exception:  # noqa: BLE001
            continue
    return None


def check_skill_provenance(
    events: list[dict[str, Any]],
    skill_keys: Optional[list[dict[str, Any]]] = None,
) -> CheckResult:
    """Walk every skill.activated.v1 event. Each must carry manifest_hash +
    signing_identity + signing_key_id, and PASS only when it also carries a
    signature that verifies, against a PINNED first-party skill-signing key,
    over the manifest digest. A signature that fails to verify is a FAIL. An
    event with no signature (the build-time fallback identity, or an identity
    string recorded without one) is DEGRADED: recorded and tamper-evident, but
    not independently verifiable.
    """
    result = CheckResult(check="skill_provenance", status="PASS")
    activations = [
        e for e in events if e.get("event_type") == SKILL_ACTIVATION_EVENT_TYPE
    ]
    result.count = len(activations)
    if not activations:
        result.notes.append(
            "no skill activation events in this bundle; nothing to verify"
        )
        return result
    if skill_keys is None:
        skill_keys = load_skill_signing_keys()

    unsigned_skills: set[str] = set()
    crypto_missing = False
    verified = 0
    for ev in activations:
        payload = _payload(ev)
        sk = f"{payload.get('skill_name')}@{payload.get('skill_version')}"
        missing = [
            f for f in ("manifest_hash", "signing_identity", "signing_key_id")
            if not payload.get(f)
        ]
        if missing:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "skill_provenance_fields_missing",
                "event_id": ev.get("event_id"),
                "skill_name": payload.get("skill_name"),
                "skill_version": payload.get("skill_version"),
                "missing": missing,
                "message": (
                    "skill activation event lacks one or more "
                    "provenance fields; the chain cannot prove which "
                    "signed skill produced this work"
                ),
            })
            continue
        signature = payload.get("manifest_signature") or ""
        if not signature:
            unsigned_skills.add(sk)
            continue
        try:
            matched = _verify_skill_signature(
                str(payload.get("manifest_hash")), str(signature), skill_keys
            )
        except _CryptoUnavailable:
            # Same degraded mode as the chain-root check: without the library
            # the signature cannot be checked, which is never a PASS.
            unsigned_skills.add(sk)
            crypto_missing = True
            continue
        if matched is None:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "skill_signature_invalid",
                "event_id": ev.get("event_id"),
                "skill_name": payload.get("skill_name"),
                "skill_version": payload.get("skill_version"),
                "message": (
                    "the signature recorded on this skill activation does not "
                    "verify over its manifest hash against a pinned Kanonik "
                    "skill-signing key (trusted_keys.json); the instruction set "
                    "cannot be attributed to a signed Kanonik skill"
                ),
            })
        elif matched.get("signing_key_id") != payload.get("signing_key_id"):
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "skill_signing_key_mismatch",
                "event_id": ev.get("event_id"),
                "skill_name": payload.get("skill_name"),
                "skill_version": payload.get("skill_version"),
                "message": (
                    "the signature verifies, but under a different pinned key "
                    "than the signing key id this activation records"
                ),
            })
        else:
            verified += 1

    if unsigned_skills:
        if result.status == "PASS":
            result.status = "DEGRADED"
        result.notes.append(
            "these AI instruction sets are recorded by name and version but carry "
            "no signature this tool can verify against a pinned Kanonik "
            "skill-signing key: "
            + ", ".join(sorted(unsigned_skills))
            + ". Their identity and version are on the chain and are "
            "tamper-evident, but the signing authority cannot be confirmed."
        )
    if crypto_missing:
        result.notes.append(
            "cryptography library not installed; cannot verify skill signatures "
            "offline. Install with `pip install -r requirements.txt`."
        )
    if result.status == "PASS":
        result.notes.append(
            f"verified the signature on {verified} skill activation events "
            "against the pinned first-party skill-signing key"
        )

    return result


# ---------------------------------------------------------------------------
# Check 6 - reproducibility tuple completeness
# ---------------------------------------------------------------------------


# Required tier-3 fields per the reproducibility requirements +
# packages/canonical-model/verifier/v1/events.go.
REPRODUCIBILITY_REQUIRED = ("canonical_inputs_hash", "prompt_version", "prompt_hash")
REPRODUCIBILITY_LLM_TIER_REQUIRED = (
    "model_provider",
    "model_id",
)
# seed is optional at tier 3 because not every provider supports it; we
# flag absence on LLM-tier verdicts as a NOTE, not a FAIL.
#
# retrieved_context_hash is likewise a NOTE, not a FAIL. The direct graders
# (conformance / soundness / link / applicability) fold the framework
# requirements and every retrieved item INTO canonical_inputs_hash
# (HashCanonicalConformanceInputs et al. hash the requirements list), so
# there is no separate retrieval blob to hash and an empty value is the
# honest state. Demanding the field universally FAILed
# every real program's export.

# An EMBEDDED verdict (inside a committed event) carries its replay tuple in a
# nested `metadata` object, and the field NAMES differ from a standalone
# verdict: prompt_content_hash (not prompt_hash) and model (not model_id). The
# metadata schema requires prompt_version + prompt_content_hash + model +
# model_provider on every verdict, so their absence is a malformed verdict and
# FAILs. canonical_inputs_hash / retrieved_context_hash / seed are omitempty on
# the embedded metadata (forward-compatible with verdicts written before those
# fields existed), so their absence is a NOTE, not a FAIL - it must not break a
# legitimate older bundle.
REPRODUCIBILITY_EMBEDDED_REQUIRED = (
    "prompt_version",
    "prompt_content_hash",
    "model_provider",
    "model",
)


def check_reproducibility_tuple(events: list[dict[str, Any]]) -> CheckResult:
    """For every verifier.verdict.v1, assert the rule-tier subset
    (canonical_inputs_hash + prompt_version + prompt_hash) is present.
    For LLM-tier verdicts (tier=='llm') additionally require
    model_provider + model_id (a missing retrieved_context_hash is only a note).
    """
    result = CheckResult(check="reproducibility_tuple_completeness", status="PASS")
    verdicts = [
        e for e in events if e.get("event_type") == "verifier.verdict.v1"
    ]
    # Embedded verdicts (inside a committed event) must be replay-checked too;
    # this check historically saw only standalone verifier.verdict.v1 events, so
    # an embedded verdict missing its tuple slipped through. Keep each committed
    # event that carries one paired with its verdict for anomaly reporting.
    embedded_pairs = [
        (e, _embedded_verdict(_payload(e)))
        for e in events
        if e.get("event_type") in COMMITTED_EVENT_TYPES
    ]
    embedded_pairs = [(e, ev) for (e, ev) in embedded_pairs if ev is not None]
    result.count = len(verdicts) + len(embedded_pairs)
    if not verdicts and not embedded_pairs:
        result.notes.append(
            "no verifier verdicts in this bundle; nothing to verify"
        )
        return result

    seed_missing_count = 0
    retrieved_hash_missing_count = 0
    for v in verdicts:
        payload = _payload(v)
        missing = [
            f for f in REPRODUCIBILITY_REQUIRED if not payload.get(f)
        ]
        if missing:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "reproducibility_tuple_incomplete",
                "event_id": v.get("event_id"),
                "tier": payload.get("tier"),
                "missing": missing,
                "message": (
                    "Verifier verdict missing replay fields; "
                    "the decision record is incomplete"
                ),
            })
            continue
        tier = payload.get("tier")
        if tier == "llm":
            llm_missing = [
                f for f in REPRODUCIBILITY_LLM_TIER_REQUIRED
                if not payload.get(f)
            ]
            if llm_missing:
                result.status = "FAIL"
                result.anomalies.append({
                    "kind": "llm_tier_tuple_incomplete",
                    "event_id": v.get("event_id"),
                    "missing": llm_missing,
                    "message": (
                        "LLM-tier verdict missing model_provider / "
                        "model_id; the decision record is incomplete"
                    ),
                })
                continue
            if not payload.get("seed"):
                seed_missing_count += 1
            if not payload.get("retrieved_context_hash"):
                retrieved_hash_missing_count += 1

    # Embedded verdicts: the replay tuple lives in the nested `metadata` object
    # with different field names (prompt_content_hash / model). A missing
    # required field is a malformed verdict -> FAIL; the omitempty fields are a
    # note.
    embedded_seed_missing = 0
    embedded_retrieved_missing = 0
    embedded_inputs_missing = 0
    for c, ev in embedded_pairs:
        md = ev.get("metadata")
        if not isinstance(md, dict) or not md:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "embedded_verdict_metadata_missing",
                "event_id": c.get("event_id"),
                "event_type": c.get("event_type"),
                "message": (
                    "the verdict embedded in this committed event carries no "
                    "metadata envelope; the decision record is incomplete"
                ),
            })
            continue
        missing = [f for f in REPRODUCIBILITY_EMBEDDED_REQUIRED if not md.get(f)]
        if missing:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "embedded_reproducibility_tuple_incomplete",
                "event_id": c.get("event_id"),
                "event_type": c.get("event_type"),
                "missing": missing,
                "message": (
                    "embedded Verifier verdict missing required replay fields "
                    "(prompt_version / prompt_content_hash / model / "
                    "model_provider); the decision record is incomplete"
                ),
            })
            continue
        if not md.get("canonical_inputs_hash"):
            embedded_inputs_missing += 1
        if not md.get("seed"):
            embedded_seed_missing += 1
        if not md.get("retrieved_context_hash"):
            embedded_retrieved_missing += 1

    if embedded_pairs:
        result.notes.append(
            f"walked {len(embedded_pairs)} embedded verdicts inside committed "
            "events for the replay tuple (metadata envelope)"
        )
    if embedded_inputs_missing:
        result.notes.append(
            f"{embedded_inputs_missing} embedded verdicts have no "
            "canonical_inputs_hash; expected for verdicts sealed before that "
            "field existed (omitempty, forward-compatible) - a note, not a fail"
        )
    if embedded_seed_missing or embedded_retrieved_missing:
        result.notes.append(
            f"{embedded_seed_missing} embedded verdicts have no seed and "
            f"{embedded_retrieved_missing} no separate retrieved_context_hash; "
            "expected (provider seedless / retrieval folded into "
            "canonical_inputs_hash)"
        )

    if seed_missing_count > 0:
        result.notes.append(
            f"{seed_missing_count} LLM-tier verdicts have no seed; "
            "expected when the provider does not accept one. "
            "The decision still records the prompt version and model used."
        )
    if retrieved_hash_missing_count > 0:
        result.notes.append(
            f"{retrieved_hash_missing_count} LLM-tier verdicts have no "
            "separate retrieved_context_hash; expected for the direct "
            "graders, which fold the retrieved requirements into "
            "canonical_inputs_hash. The decision still records the prompt version, model and "
            "canonical_inputs_hash; the prompt text stays with Kanonik."
        )

    if result.status == "PASS":
        result.notes.append(
            f"all {result.count} verdicts (standalone + embedded) carry the "
            "required tier-3 reproducibility fields"
        )
    return result


# ---------------------------------------------------------------------------
# Check 7 - prompt integrity (deterministic)
# ---------------------------------------------------------------------------


def check_prompt_integrity(
    events: list[dict[str, Any]], bundle_dir: Path
) -> CheckResult:
    """Deterministic Tier-3 prompt-integrity verification .

    For every LLM-tier verifier.verdict.v1, assert its prompt_hash is a genuine
    released Kanonik Verifier prompt - i.e. present in the bundle's
    chain/verifier_prompt_registry.json (SHA-256 hashes only; the prompt TEXT
    is never shipped, so this recomputation exposes no prompt IP). A verdict
    citing a prompt_hash NOT in the registry means the recorded verdict did not
    use a released prompt: fabricated or tampered.

    Rule-tier verdicts (prompt_version 'rule-tier-*') and audit '-stub'
    versions have no file-backed LLM prompt and are carved out - the rule tier
    is deterministic code, not a prompt.
    """
    result = CheckResult(check="prompt_integrity", status="PASS")
    registry = _read_json(bundle_dir / "chain" / "verifier_prompt_registry.json")
    prompts = registry.get("prompts") if isinstance(registry, dict) else None
    if not isinstance(prompts, dict) or not prompts:
        result.status = "DEGRADED"
        result.notes.append(
            "chain/verifier_prompt_registry.json absent or empty - cannot "
            "confirm LLM-tier prompt_hash values against the released prompt "
            "set (an older bundle predating the prompt registry). Tuple "
            "completeness (check #6) still holds; this only downgrades the "
            "Tier-3 independent prompt-integrity assurance."
        )
        return result

    known = set(prompts.values())
    verdicts = [
        e for e in events if e.get("event_type") == "verifier.verdict.v1"
    ]
    checked = 0
    for v in verdicts:
        payload = _payload(v)
        tier = payload.get("tier")
        prompt_version = str(payload.get("prompt_version") or "")
        # Only LLM-tier verdicts use a file-backed Verifier prompt.
        if tier != "llm" or prompt_version.endswith("-stub"):
            continue
        prompt_hash = payload.get("prompt_hash") or ""
        checked += 1
        if prompt_hash not in known:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "llm_prompt_not_recognized",
                "event_id": v.get("event_id"),
                "prompt_version": prompt_version,
                "prompt_hash": prompt_hash,
                "message": (
                    "LLM-tier verdict cites a prompt_hash that is NOT a "
                    "released Kanonik Verifier prompt (absent from the "
                    "bundle's chain/verifier_prompt_registry.json); the "
                    "recorded verdict did not use a genuine released prompt "
                    "- fabricated or tampered"
                ),
            })

    # Embedded verdicts (inside committed events) cite their released prompt in
    # nested metadata.prompt_content_hash - a DIFFERENT field name than the
    # standalone prompt_hash. Validate each PRESENT one against the SAME released
    # registry so a committed event whose embedded verdict cites a fabricated
    # prompt cannot pass Tier-3 prompt-integrity. A genuine embedded verdict
    # cites a released prompt whose content hash is in this registry (same
    # 'sha256:' encoding as standalone verdicts), so a real bundle passes. An
    # ABSENT hash is left to check_reproducibility_tuple (which requires it);
    # '-stub' prompt versions are carved out exactly as for standalone verdicts.
    embedded_checked = 0
    for e in events:
        if e.get("event_type") not in COMMITTED_EVENT_TYPES:
            continue
        ev = _embedded_verdict(_payload(e))
        if not isinstance(ev, dict):
            continue
        md = ev.get("metadata")
        if not isinstance(md, dict):
            continue
        prompt_version = str(md.get("prompt_version") or "")
        if prompt_version.endswith("-stub"):
            continue
        pch = md.get("prompt_content_hash") or ""
        if not pch:
            continue
        embedded_checked += 1
        if pch not in known:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "embedded_llm_prompt_not_recognized",
                "event_id": e.get("event_id"),
                "event_type": e.get("event_type"),
                "prompt_version": prompt_version,
                "prompt_content_hash": pch,
                "message": (
                    "embedded Verifier verdict cites a prompt_content_hash "
                    "that is NOT a released Kanonik Verifier prompt (absent "
                    "from the bundle's chain/verifier_prompt_registry.json); "
                    "the recorded verdict did not use a genuine released "
                    "prompt - fabricated or tampered"
                ),
            })

    result.count = checked + embedded_checked
    if result.status == "PASS":
        if result.count == 0:
            result.notes.append(
                "no LLM-tier verdicts in this bundle; nothing to verify "
                "against the prompt registry (rule-tier verdicts have no "
                "file-backed prompt)"
            )
        else:
            result.notes.append(
                f"verified {checked} standalone + {embedded_checked} embedded "
                "verdict prompt hash value(s) against the released Verifier "
                "prompt registry; each used a genuine released prompt"
            )
    return result


# ---------------------------------------------------------------------------
# Optional check - per-file checksum integrity
# ---------------------------------------------------------------------------


PACKAGE_SEAL_FILE = "package_seal.json"
PACKAGE_SEAL_VERSION = "kanonik.package-seal.v1"
UNSEALED_NOTE = (
    "the files of this package are not sealed in this package version: MANIFEST.json is not signed, so a file "
    "changed together with its listed checksum cannot be detected here. Each file still matches its listed "
    "checksum. Ask for a current package"
)
# Files an operating system or a run of this checker may leave beside the package; they are not package
# content. The checker's own bytecode is exempt only where the checker lives (chain/__pycache__/*.pyc): a
# __pycache__ folder anywhere else, say under Records/, is a place to hide a document, and fails.
_IGNORED_FILE_NAMES = frozenset({".DS_Store", "Thumbs.db", "desktop.ini"})
_CHECKER_CACHE = re.compile(r"(?:Verification/)?chain/__pycache__/[^/]+\.pyc")


def _is_package_noise(rel: str) -> bool:
    return rel.split("/")[-1] in _IGNORED_FILE_NAMES or _CHECKER_CACHE.fullmatch(rel) is not None


def _package_file_listing(package_root: Path, machine_dir: Path) -> set[str]:
    """Every file under the package folder by its path from there, except the manifest and the seal."""
    found: set[str] = set()
    skip = {
        (machine_dir / "MANIFEST.json").resolve(),
        (machine_dir / PACKAGE_SEAL_FILE).resolve(),
    }
    for f in package_root.rglob("*"):
        if not f.is_file() or f.resolve() in skip:
            continue
        rel = f.relative_to(package_root).as_posix()
        if not _is_package_noise(rel):
            found.add(rel)
    return found


SEAL_REMOVED_MESSAGE = (
    "this package was exported with a seal (its signed chain root says so) but the seal file is missing: the seal "
    "was removed, or files were changed and the seal with them. Do not rely on this package."
)
PREDATES_SEAL_MESSAGE = (
    "this package carries a chain root from before packages were sealed, signed after the day Kanonik began "
    "sealing them: it was exported by an older version, or its root was swapped. Ask for a current package."
)
_RFC3339 = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})")


def _instant(value: Any) -> Optional[int]:
    """Whole seconds since the epoch of an RFC 3339 instant, or None. The fraction is ignored: the instants
    this compares are whole seconds."""
    if not isinstance(value, str):
        return None
    m = _RFC3339.fullmatch(value.strip())
    if m is None:
        return None
    y, mo, d, h, mi, sec = (int(g) for g in m.groups()[:6])
    zone = m.group(7)
    try:
        moment = datetime(y, mo, d, h, mi, sec, tzinfo=timezone.utc)
    except ValueError:
        return None
    offset = 0
    if zone != "Z":
        offset = (int(zone[1:3]) * 3600 + int(zone[4:6]) * 60) * (1 if zone[0] == "+" else -1)
    return int(moment.timestamp()) - offset


def seal_claim(
    chain_root: Optional[dict[str, Any]],
    trusted_keys: Optional[list[dict[str, Any]]],
) -> Optional[str]:
    """Does the package claim to be sealed, by something the attacker cannot change without breaking a signature?
    Returns None (no claim: an older package), "v3" (the root's version says so) or "predates" (the root was
    signed by a pinned key from the day that key requires seals, yet is not a v3 root). A claim read from the
    version string is enforced even when the signature cannot be checked here: a genuine v3 package always has
    its seal, and changing the string breaks the root signature check."""
    if not isinstance(chain_root, dict):
        return None
    version = str(chain_root.get("version") or chain_root.get("Version") or DEFAULT_CHAIN_ROOT_VERSION)
    if version == CHAIN_ROOT_V3:
        return "v3"
    signature = chain_root.get("signature") or ""
    if not signature or not trusted_keys or not any(k.get("seal_required_from") for k in trusted_keys):
        return None
    try:
        # Decoded exactly as check_chain_root_signature decodes it: a signature that check accepts must be one this
        # reads as signed too, or a stray byte in the base64 would hide the claim.
        raw, payload = _canonical_b64(signature), build_chain_root_signed_payload(chain_root)
        # Every pinned entry whose key verifies the signature counts, and the EARLIEST date among them wins: the
        # policy must not depend on which of two entries for one key comes first in the list.
        dates = [k.get("seal_required_from") or "" for k in _verifying_keys(raw, payload, trusted_keys)]
    except Exception:  # noqa: BLE001 - no crypto library or a malformed root: the signature check reports it
        return None
    dates = [d for d in dates if d]
    if not dates:
        return None
    signed = _instant(chain_root.get("signed_at"))
    for d in dates:
        required = _instant(d)
        if required is None or signed is None or signed >= required:
            return "predates"  # an unreadable date on either side fails closed
    return None


def check_package_seal(
    seal_bytes: bytes,
    manifest: dict[str, Any],
    manifest_bytes: bytes,
    chain_root: Optional[dict[str, Any]],
    trusted_keys: Optional[list[dict[str, Any]]],
    public_key_pem: Optional[bytes],
    result: CheckResult,
    package_root: Path,
    machine_dir: Path,
) -> None:
    """Verify package_seal.json: the chain-root key signed the SHA-256 of the exact
    MANIFEST.json bytes and the SHA-256 of every file the package lists. Anything the seal does not
    cover, or any file that differs from it, fails the check and is named. Mutates result."""
    try:
        envelope = json.loads(seal_bytes)
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise ValueError("expected a payload and signature envelope")
        payload_bytes = base64.b64decode(envelope["payload"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        payload = json.loads(payload_bytes)
        if not isinstance(payload, dict) or set(payload) != {
            "version", "tenant_id", "chain_root_sha256", "signing_key_id", "manifest_sha256", "files"
        } or canonical_marshal(payload) != payload_bytes:
            raise ValueError("seal payload must use the canonical schema")
        if payload["version"] != PACKAGE_SEAL_VERSION:
            raise ValueError("unknown package seal signing domain")
        if not chain_root or not chain_root.get("signature"):
            raise ValueError("the seal needs the signed chain root of this package")
        root_bytes = build_chain_root_signed_payload(chain_root)
        if payload["chain_root_sha256"] != hashlib.sha256(root_bytes).hexdigest():
            raise ValueError("the seal belongs to a different chain root")
        if payload["tenant_id"] != chain_root.get("tenant_id") or payload["signing_key_id"] != chain_root.get("signing_key_id"):
            raise ValueError("the seal's tenant or key differs from the chain root")
        sealed = payload["files"]
        if not isinstance(sealed, dict) or not sealed or not all(
            isinstance(k, str) and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for k, v in sealed.items()
        ):
            raise ValueError("the sealed file list is malformed")
    except Exception as exc:  # noqa: BLE001 - untrusted package, fail closed
        result.status = "FAIL"
        result.anomalies.append({"kind": "package_seal_invalid", "message": str(exc) or "package seal is invalid"})
        return
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        if trusted_keys:
            matched = _verify_sig_against_trusted(signature, payload_bytes, trusted_keys)
            if matched is None:
                raise ValueError(
                    "the package seal is not signed by a pinned Kanonik key: the package, its file list or "
                    "the seal may have been rebuilt with another key"
                )
            pem = matched["pem"]
            pub = load_pem_public_key(pem.encode() if isinstance(pem, str) else pem)
            independent = True
        else:
            if not public_key_pem or not public_key_pem.strip():
                raise ValueError("no pinned key and no key in the package; cannot check the seal")
            pub = load_pem_public_key(public_key_pem)
            independent = False
        if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP384R1):
            raise ValueError("the package seal requires an ECDSA P-384 key")
        if not independent:
            pub.verify(signature, payload_bytes, ec.ECDSA(hashes.SHA384()))
        # The one key must also have signed the chain root this seal names.
        pub.verify(base64.b64decode(chain_root["signature"], validate=True), root_bytes, ec.ECDSA(hashes.SHA384()))
    except ImportError:
        if result.status == "PASS":
            result.status = "DEGRADED"
        result.notes.append("cryptography library not installed; cannot check the package seal")
        return
    except Exception as exc:  # noqa: BLE001
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "package_seal_invalid",
            "message": str(exc) or "the package seal signature does not verify",
        })
        return
    if not independent and result.status == "PASS":
        result.status = "DEGRADED"
        result.notes.append(
            "the package seal was verified only against the key the package carries, not a pinned Kanonik key"
        )
    # The seal verified. Now hold the package to it.
    if hashlib.sha256(manifest_bytes).hexdigest() != payload["manifest_sha256"]:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "manifest_changed",
            "message": "MANIFEST.json is not the file that was sealed: it was changed after the package was made",
        })
    listed = manifest.get("file_checksums", {}) or {}
    for rel in sorted(set(sealed) | set(listed)):
        if rel not in sealed:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "file_not_sealed", "path": rel,
                "message": "MANIFEST.json lists a file the seal does not cover",
            })
        elif rel not in listed:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "file_removed_from_list", "path": rel,
                "message": "the seal covers a file MANIFEST.json no longer lists",
            })
        elif listed[rel] != sealed[rel]:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "checksum_not_sealed", "path": rel,
                "message": "MANIFEST.json lists a checksum for this file that differs from the sealed one",
            })
    for rel, want in sealed.items():
        f = package_root / rel
        if not f.is_file():
            result.status = "FAIL"
            result.anomalies.append({"kind": "sealed_file_missing", "path": rel, "message": "a sealed file is not in the package"})
        elif hashlib.sha256(f.read_bytes()).hexdigest() != want:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "sealed_file_changed", "path": rel,
                "message": "this file differs from the file that was sealed",
            })
    for rel in sorted(_package_file_listing(package_root, machine_dir) - set(sealed)):
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "file_not_sealed", "path": rel,
            "message": "this file is in the package but was not sealed",
        })
    if result.status in ("PASS", "DEGRADED") and not result.anomalies:
        result.notes.append(
            f"the package seal verified: Kanonik's key signed the file list, and all {len(sealed)} files match it"
        )


def check_file_checksums(
    bundle_dir: Path,
    manifest: Optional[dict[str, Any]],
    seal_bytes: Optional[bytes] = None,
    manifest_bytes: Optional[bytes] = None,
    chain_root: Optional[dict[str, Any]] = None,
    trusted_keys: Optional[list[dict[str, Any]]] = None,
    public_key_pem: Optional[bytes] = None,
    machine_dir: Optional[Path] = None,
) -> CheckResult:
    """Verify every listed file against its SHA-256 in MANIFEST.json, then the seal that binds that list to
    the signing key. A package with no seal reads DEGRADED ("Passed with notes"), never PASS:
    its file list is unsigned, so a file edited together with its listed checksum would go unseen.
    """
    result = CheckResult(check="file_checksums", status="PASS")
    if manifest is None:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "manifest_missing",
            "message": "MANIFEST.json missing from bundle",
        })
        return result
    minimum = manifest.get("min_verifier_version")
    if minimum is not None and (
        not isinstance(minimum, str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", minimum) is None
        or _version_tuple(minimum) > _version_tuple(MAX_SUPPORTED_BUNDLE_REQUIREMENT)
    ):
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "bundle_requirement_unsupported",
            "message": "This bundle requires checks not supported by this toolkit. Ask for a compatible checker.",
        })
        return result
    checksums = manifest.get("file_checksums", {}) or {}
    result.count = len(checksums)
    for rel_path, want in checksums.items():
        f = bundle_dir / rel_path
        if not f.exists():
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "file_missing",
                "path": rel_path,
                "message": "MANIFEST references file not in bundle",
            })
            continue
        got = hashlib.sha256(f.read_bytes()).hexdigest()
        if got != want:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "checksum_mismatch",
                "path": rel_path,
                "expected": want,
                "got": got,
                "message": "file content does not match MANIFEST checksum",
            })
    claim = seal_claim(chain_root, trusted_keys)
    if claim == "predates":
        result.status = "FAIL"
        result.anomalies.append({"kind": "chain_root_predates_seal", "message": PREDATES_SEAL_MESSAGE})
    if seal_bytes is None:
        if claim == "v3":
            result.status = "FAIL"
            result.anomalies.append({"kind": "seal_removed", "message": SEAL_REMOVED_MESSAGE})
        elif result.status == "PASS":
            result.status = "DEGRADED"
            result.notes.append(UNSEALED_NOTE)
        return result
    check_package_seal(
        seal_bytes, manifest, manifest_bytes if manifest_bytes is not None else b"", chain_root,
        trusted_keys, public_key_pem, result, bundle_dir, machine_dir or bundle_dir,
    )
    if result.status == "PASS" and not any("seal verified" in n for n in result.notes):
        result.notes.append(f"verified SHA-256 checksums on {len(checksums)} files")
    return result


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Single-record mode: one sealed record, handed to a buyer
# ---------------------------------------------------------------------------
#
# A company can hand a buyer the proof of ONE record (a saved answer behind a
# questionnaire answer, an answer set) instead of the whole export. The file
# carries the committed event with every field the chain hash covers, a
# record checkpoint (the chain-root signer's signature over this event's own
# sequence and hash), the verdict tuple, the human approval, whether a newer
# sealed version existed when the file was made, and the oldest verifier that
# reads it. Nothing about any other record is in the file, and nothing here
# needs one.

RECORD_PROOF_SCHEMA = "record_proof.v1"

# Record kinds the rule tier alone checks at the seal; they carry no LLM
# verdict by design (an answer set is a form filled from saved answers that
# each carry their own).
RECORD_RULE_TIER_ONLY_KINDS = frozenset({
    "questionnaire_response",
    "obligation",
    "lens_decision",
    "lens_applicability",
    "migration_summary",
    "policy_acknowledgement",
})

RECORD_VERDICT_REQUIRED = ("model", "model_provider", "prompt_version", "prompt_content_hash")

KNOWN_DECISION_BASES = frozenset({
    DECISION_BASIS_SEALED_BY_OTHER,
    DECISION_BASIS_AUTHOR_SELF_SEAL_SOLE_SEALER,
    DECISION_BASIS_AUTHOR_SELF_SEAL_RECORD_KIND,
})


def _version_tuple(value: str) -> tuple[int, ...]:
    # ASCII digits only (str.isdigit() accepts "\u00b2" and other scripts, and int() then crashes or disagrees with
    # verify.mjs). Trailing zeros are dropped so 2.7.19.0 equals 2.7.19, as verify.mjs pads with zeros.
    parts = []
    for piece in str(value).strip().split("."):
        digits = "".join(ch for ch in piece if "0" <= ch <= "9")
        parts.append(int(digits) if digits else 0)
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def check_record_schema(proof: dict[str, Any]) -> CheckResult:
    """The file names a schema this verifier reads and a minimum verifier
    version this verifier meets. A newer file is refused, never guessed at."""
    result = CheckResult(check="record_schema_and_version", status="PASS", count=1)
    schema = proof.get("schema_version")
    if schema != RECORD_PROOF_SCHEMA:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_schema_unknown",
            "message": f"schema_version is {schema!r}; this verifier reads {RECORD_PROOF_SCHEMA}",
        })
    minimum = proof.get("min_verifier_version")
    if not minimum:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_min_version_missing",
            "message": "the file names no minimum verifier version",
        })
    elif _version_tuple(minimum) > _version_tuple(VERIFIER_VERSION):
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_verifier_too_old",
            "message": (
                f"the file needs verifier {minimum} or later; this is {VERIFIER_VERSION}. "
                "Ask the sender for the current toolkit."
            ),
        })
    else:
        result.notes.append(f"file needs verifier {minimum}; this is {VERIFIER_VERSION}")
    return result


def check_record_event_hash(proof: dict[str, Any]) -> CheckResult:
    """Recompute the event hash from the record's own bytes and compare it
    with the hash the file states; check the event is the record it says."""
    result = CheckResult(check="record_event_hash", status="PASS")
    event = proof.get("event")
    if not isinstance(event, dict) or not event:
        result.status = "FAIL"
        result.anomalies.append({"kind": "record_event_missing", "message": "the file carries no event"})
        return result
    result.count = 1
    try:
        computed = compute_event_hash(event)
    except Exception as e:  # noqa: BLE001
        result.status = "FAIL"
        result.anomalies.append({"kind": "record_event_unhashable", "message": f"the event cannot be hashed: {e}"})
        return result
    stated = event.get("event_hash") or ""
    if base64.b64encode(computed).decode("ascii") != stated:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_event_hash_mismatch",
            "message": "the event's content does not hash to the event_hash it states: a byte changed after the seal",
        })
        return result
    kind = proof.get("kind") or ""
    if kind and event.get("entity_type") != kind:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_kind_mismatch",
            "message": f"the file says kind {kind!r} but the event is a {event.get('entity_type')!r}",
        })
    if not str(event.get("event_type", "")).endswith(".committed.v1"):
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_not_a_seal",
            "message": f"the event is {event.get('event_type')!r}, not a sealed (committed) record",
        })
    payload = _payload(event)
    canonical_id = proof.get("canonical_id") or ""
    stated_id = payload.get("canonical_id") or event.get("entity_id") or ""
    if canonical_id and stated_id and canonical_id != stated_id:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_id_mismatch",
            "message": "the file's canonical_id is not the record the event carries",
        })
    if result.status == "PASS":
        result.notes.append("event hash recomputed from the record's own bytes and matches")
    return result


def check_record_checkpoint_signature(proof: dict[str, Any], trusted_keys: Optional[list[dict[str, Any]]] = None) -> CheckResult:
    """Verify the record checkpoint: the chain-root signer's ECDSA P-384 +
    SHA-384 signature over this event's own sequence and hash."""
    result = CheckResult(check="record_checkpoint_signature", status="PASS")
    cp = proof.get("checkpoint")
    event = proof.get("event") if isinstance(proof.get("event"), dict) else {}
    if not isinstance(cp, dict) or not cp:
        result.status = "FAIL"
        result.anomalies.append({"kind": "record_checkpoint_missing", "message": "the file carries no signed checkpoint"})
        return result
    result.count = 1
    if (cp.get("version") or "") != "record-v1":
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_checkpoint_version_unknown",
            "message": f"checkpoint version {cp.get('version')!r}; this verifier reads record-v1",
        })
        return result
    if (cp.get("event_hash") or "") != (event.get("event_hash") or ""):
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_checkpoint_hash_mismatch",
            "message": "the checkpoint signs a different event hash than the event in the file",
        })
        return result
    try:
        same_seq = event_hash_mod._strict_seq(cp.get("sequence_number", -1)) == event_hash_mod._strict_seq(event.get("sequence_number", -2))
    except ValueError:
        same_seq = False
    if not same_seq:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_checkpoint_sequence_mismatch",
            "message": "the checkpoint names a different sequence number than the event",
        })
        return result
    if (cp.get("tenant_id") or "") != (event.get("tenant_id") or ""):
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_checkpoint_tenant_mismatch",
            "message": "the checkpoint and the event name different workspaces",
        })
        return result
    sig_b64 = cp.get("signature") or ""
    if not sig_b64:
        result.status = "FAIL"
        result.anomalies.append({"kind": "record_checkpoint_unsigned", "message": "the checkpoint carries no signature"})
        return result
    try:
        signature = base64.b64decode(sig_b64)
    except Exception as e:  # noqa: BLE001
        result.status = "FAIL"
        result.anomalies.append({"kind": "record_checkpoint_b64_invalid", "message": f"checkpoint signature is not valid base64: {e}"})
        return result
    try:
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        from cryptography.hazmat.primitives.serialization import load_pem_public_key  # noqa: PLC0415
    except ImportError:
        result.status = "DEGRADED"
        result.notes.append(
            "the cryptography package is not installed, so the checkpoint signature was not "
            "checked; install requirements.txt and run again. The event hash check still holds."
        )
        return result
    try:
        signed = build_record_checkpoint_signed_payload(cp)
    except Exception as e:  # noqa: BLE001
        result.status = "FAIL"
        result.anomalies.append({"kind": "record_signed_payload_rebuild_failed", "message": str(e)})
        return result

    # Verify against the PINNED trust anchor, never the checkpoint's own key.
    trusted_keys = trusted_keys or []
    if trusted_keys:
        matched = _verify_sig_against_trusted(signature, signed, trusted_keys)
        if matched is None:
            result.status = "FAIL"
            result.anomalies.append({
                "kind": "record_checkpoint_key_untrusted",
                "signing_key_id": cp.get("signing_key_id") or "",
                "message": (
                    "the checkpoint signature does not verify against any PINNED Kanonik key "
                    "(trusted_keys.json / --trusted-keys / --online): re-signed with a foreign key, "
                    "tampered, or a key not yet pinned. The checkpoint's own signing_public_key_pem "
                    "is intentionally NOT trusted."
                ),
            })
            return result
        env = matched.get("env") or ""
        if matched.get("class") == "sample":
            result.status = "DEGRADED"
            result.notes.append(SAMPLE_KEY_NOTE)
        elif env == "production":
            result.notes.append(
                "ECDSA P-384 + SHA-384 signature verified against Kanonik's PINNED PRODUCTION key "
                f"(id {matched.get('signing_key_id')!r}); record attested by Kanonik at {cp.get('signed_at')}"
            )
        else:
            result.status = "DEGRADED"
            label = matched.get("label") or env or "non-production"
            result.notes.append(
                f"signature verified against a pinned NON-PRODUCTION Kanonik key (env={env or 'dev'}, {label}); "
                "the record is structurally sound but is NOT attestable to Kanonik's PRODUCTION key. "
                "Expected for integration/dev proofs."
            )
        return result

    # No pinned trust anchor: fall back to the checkpoint's own key, DEGRADED.
    try:
        pem = base64.b64decode(cp.get("signing_public_key_pem") or "")
    except Exception as e:  # noqa: BLE001
        result.status = "FAIL"
        result.anomalies.append({"kind": "record_checkpoint_b64_invalid", "message": f"checkpoint public key is not valid base64: {e}"})
        return result
    if not pem:
        result.status = "FAIL"
        result.anomalies.append({"kind": "record_public_key_missing", "message": "no pinned trust anchor and the checkpoint carries no signing public key"})
        return result
    try:
        key = load_pem_public_key(pem)
    except Exception as e:  # noqa: BLE001
        result.status = "FAIL"
        result.anomalies.append({"kind": "record_public_key_parse_failed", "message": f"the signing public key does not parse: {e}"})
        return result
    try:
        key.verify(signature, signed, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_signature_verification_failed",
            "message": "ECDSA P-384 + SHA-384 signature does NOT verify over the checkpoint (tampered, forged, or the wrong key)",
        })
        return result
    except Exception as e:  # noqa: BLE001
        result.status = "FAIL"
        result.anomalies.append({"kind": "record_signature_verification_error", "message": str(e)})
        return result
    result.status = "DEGRADED"
    result.notes.append(
        "no pinned Kanonik trust anchor was available, so the checkpoint signature was verified only "
        "against the key the proof carries; that is not an independent check."
    )
    return result


def check_record_verdict(proof: dict[str, Any]) -> CheckResult:
    """A graded record carries its verdict with the replay fields; a rule-tier
    kind carries none by design and says so."""
    result = CheckResult(check="record_verdict", status="PASS", count=1)
    event = proof.get("event") if isinstance(proof.get("event"), dict) else {}
    kind = proof.get("kind") or event.get("entity_type") or ""
    payload = _payload(event)
    verdict = payload.get("verifier_verdict")
    if kind in RECORD_RULE_TIER_ONLY_KINDS:
        result.notes.append(f"a {kind} is checked by the rule tier at the seal and carries no model verdict by design")
        if verdict:
            result.notes.append("a verdict is present anyway; not required")
        return result
    # A graded (non-rule-tier) kind must carry its verdict; an absent OR a
    # present-but-malformed one FAILs here. This record-mode strictness is
    # PRESERVED exactly as it was before the committed-kind coverage pass.
    # NOTE (deliberate record/bundle asymmetry - do not "fix" without
    # authorization): the BUNDLE check adds NEW coverage for the historical-
    # optional kinds (asset/risk/vendor/soa_decision) as DEGRADED, because those
    # kinds were previously unchecked there and the field is schema-optional, so
    # DEGRADE is net-tightening. LOWERING this pre-existing record-mode FAIL to
    # match would be a guarantee RELAXATION a coverage change is not authorized
    # to make. Reconciling the two severities for a historical-optional kind is
    # deferred to the same guarantee decision as the schema-required follow-up.
    if not isinstance(verdict, dict) or not verdict:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_verdict_missing",
            "message": f"a sealed {kind or 'record'} must carry its verifier verdict; none is embedded",
        })
        return result
    outcome = str(verdict.get("outcome") or "").lower()
    if outcome != "approved":
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_verdict_not_approved",
            "message": f"the embedded verdict outcome is {outcome or 'absent'!r}, not approved",
        })
    meta = verdict.get("metadata") if isinstance(verdict.get("metadata"), dict) else {}
    missing = [k for k in RECORD_VERDICT_REQUIRED if not meta.get(k)]
    if missing:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_verdict_tuple_incomplete",
            "message": "the verdict lacks replay fields: " + ", ".join(missing),
        })
    if not meta.get("canonical_inputs_hash"):
        result.notes.append("canonical_inputs_hash absent: the inputs cannot be matched byte for byte against the record")
    stated = proof.get("verdict") if isinstance(proof.get("verdict"), dict) else None
    if stated and meta.get("prompt_content_hash") and stated.get("prompt_hash") and stated["prompt_hash"] != meta["prompt_content_hash"]:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_verdict_summary_mismatch",
            "message": "the file's verdict summary names a different prompt hash than the sealed event",
        })
    if result.status == "PASS":
        result.notes.append(
            f"verdict approved by {meta.get('model_provider')}/{meta.get('model')} under prompt {meta.get('prompt_version')}"
        )
    return result


def check_record_approval(proof: dict[str, Any]) -> CheckResult:
    """The human seal: who approved and when are in the sealed event itself;
    the approval event's decision basis says why one person could."""
    result = CheckResult(check="record_approval", status="PASS", count=1)
    event = proof.get("event") if isinstance(proof.get("event"), dict) else {}
    kind = proof.get("kind") or event.get("entity_type") or ""
    payload = _payload(event)
    if not payload.get("approved_by_subject") or not payload.get("committed_at"):
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_approval_missing",
            "message": "the sealed event names no approver or no seal time",
        })
        return result
    approval = proof.get("approval") if isinstance(proof.get("approval"), dict) else {}
    if approval.get("approved_by_subject") and approval["approved_by_subject"] != payload["approved_by_subject"]:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_approver_mismatch",
            "message": "the file's approval names a different approver than the sealed event",
        })
    basis = approval.get("decision_basis") or ""
    if not basis:
        result.status = "DEGRADED"
        result.notes.append(
            "no approval event is attached, so the decision basis (why one person could seal) is not shown; "
            "the seal itself is in the sealed event"
        )
    elif basis not in KNOWN_DECISION_BASES:
        result.status = "FAIL"
        result.anomalies.append({"kind": "record_decision_basis_unknown", "message": f"decision_basis {basis!r} is not one this verifier knows"})
    elif basis == DECISION_BASIS_AUTHOR_SELF_SEAL_RECORD_KIND and kind not in CATALOGUE_DEFAULT_AUTHOR_SELF_SEAL:
        result.status = "FAIL"
        result.anomalies.append({
            "kind": "record_self_seal_kind_not_allowed",
            "message": f"a {kind} is not a kind its author may seal alone under the catalogue default",
        })
    if result.status == "PASS":
        result.notes.append(f"sealed by {payload['approved_by_subject']} at {payload['committed_at']}; basis {basis}")
    return result


def check_record_currency(proof: dict[str, Any]) -> CheckResult:
    """Whether the record was still the latest sealed version of its lineage
    when the file was made. Not a failure: a superseded version verifies, it
    is simply not the current one."""
    result = CheckResult(check="record_currency", status="PASS", count=1)
    if proof.get("is_latest_for_entity") is True:
        result.notes.append(f"latest sealed version as of {proof.get('exported_at')}")
        return result
    result.status = "DEGRADED"
    newer = proof.get("latest_canonical_id") or "a later version"
    result.notes.append(
        f"a newer sealed version ({newer}) existed when this file was made on {proof.get('exported_at')}; "
        "this record verifies as the version it is, not as the current one. Ask the sender for the current file."
    )
    return result


def run_record_checks(proof: dict[str, Any], trusted_keys: Optional[list[dict[str, Any]]] = None) -> list[CheckResult]:
    """Execute the single-record checks in priority order."""
    return [
        check_record_schema(proof),
        check_record_event_hash(proof),
        check_record_checkpoint_signature(proof, trusted_keys),
        check_record_verdict(proof),
        check_record_approval(proof),
        check_record_currency(proof),
    ]


def run_record_mode(path: Path, trusted_keys: Optional[list[dict[str, Any]]] = None, online_keys: Optional[dict[str, str]] = None) -> int:
    """Verify one single-record proof file and print the report."""
    try:
        proof = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        print(f"error: could not read the proof file: {e}", file=sys.stderr)
        return 2
    if not isinstance(proof, dict):
        print("error: the proof file is not a JSON object", file=sys.stderr)
        return 2
    try:
        results = run_record_checks(proof, trusted_keys)
    except Exception as e:  # noqa: BLE001
        print(f"error: verifier crashed: {e}", file=sys.stderr)
        return 2
    summary = summarise(results)
    summary["mode"] = "record"
    summary["online_keys"] = online_keys or {"state": "not_requested", "note": ""}
    summary["record"] = {
        "kind": proof.get("kind"),
        "canonical_id": proof.get("canonical_id"),
        "exported_at": proof.get("exported_at"),
    }

    print("You can check this record without asking Kanonik. What you still rely on Kanonik for: the pinned signing keys and the prompt registry in this checker.", file=sys.stderr)
    print("", file=sys.stderr)
    print(f"Record verification: {result_word(summary['overall_status'])}", file=sys.stderr)
    print(f"Checker version: {VERIFIER_VERSION}", file=sys.stderr)
    print(f"Record: {proof.get('kind') or 'unknown kind'} {proof.get('canonical_id') or ''}".rstrip(), file=sys.stderr)
    if online_keys_line(online_keys):
        print(online_keys_line(online_keys), file=sys.stderr)
    by_check = {r.check: r for r in results}
    sig = by_check.get("record_checkpoint_signature")
    sig_str = "yes" if sig and sig.status == "PASS" else ("degraded" if sig and sig.status == "DEGRADED" else "no")
    print(f"Signature verified: {_signature_words(sig_str)}", file=sys.stderr)
    cur = by_check.get("record_currency")
    print(f"Latest version at export: {'yes' if cur and cur.status == 'PASS' else 'no'}", file=sys.stderr)
    print("", file=sys.stderr)
    print("Kanonik single-record proof - offline verification", file=sys.stderr)
    print("=" * 50, file=sys.stderr)
    for r in results:
        marker = {"PASS": "passed ", "FAIL": "failed ", "DEGRADED": "notes  "}.get(r.status, "??? ")
        print(f"[{marker}] {r.check}", file=sys.stderr)
        for note in r.notes:
            print(f"        {note}", file=sys.stderr)
        for a in r.anomalies:
            print(f"        - {a.get('kind', 'anomaly')}: {a.get('message', '')}", file=sys.stderr)
    print(
        f"\nOverall: {result_word(summary['overall_status'])}  "
        f"({summary['summary'].get('PASS', 0)} passed, "
        f"{summary['summary'].get('DEGRADED', 0)} with notes, "
        f"{summary['summary'].get('FAIL', 0)} failed)",
        file=sys.stderr,
    )
    _say_json_follows()
    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if summary["overall_status"] == "PASS" else 1


# ---------------------------------------------------------------------------
# Disclosure file (`--disclosure`): a signed kanonik-disclosure/v1 manifest a company published
# ---------------------------------------------------------------------------
#
# The file is {"manifest": {...}, "signature": {"version", "manifest_sha384", "value"}}. The chain-root key signed
# the canonical JSON of {version: "disclosure-v1", manifest_sha384, publisher_public_id, issued_at, key_id}; the
# version string keeps a record-v1 signature from verifying here and the reverse. This checker re-derives the digest
# and the signing input from the manifest in the file, picks the pinned key by the manifest's key_id and verifies
# against that. It never trusts a key the file carries.
#
# HONEST LIMIT: the signature shows that Kanonik attested this text was approved and sealed in the named event
# (source_event_hash) and that it is unchanged since. Unlike a single-record proof it cannot recompute that event's
# hash, and it never says the text is true.
#
# Outcomes (the headline word of the report; verify.mjs and verify.html use the same words):
#   VERIFIED                  signed by a pinned production key, unchanged.
#   VERIFIED_NON_PRODUCTION   signed by a pinned integration or sample key; structurally sound, not attestable.
#   UNKNOWN_ISSUER            the key id is not one this checker pins (the checker may be old; the file is not
#                             shown to be forged).
#   BAD_SIGNATURE             the key id is pinned but the signature does not verify: changed after signing,
#                             signed by another key, or damaged.
#   KEY_REVOKED               signed by a key Kanonik has revoked (compromise).
#   UNKNOWN_SCHEMA            a manifest schema or signature version this checker does not read. Refused, not guessed.
#   VERIFIER_TOO_OLD          the file needs a newer checker.
#   MALFORMED                 not a disclosure file, or internally inconsistent.
DISCLOSURE_MANIFEST_SCHEMA = "kanonik-disclosure/v1"
DISCLOSURE_SIGNATURE_VERSION = "disclosure-v1"
DISCLOSURE_CONSUMER_VERSION = 1  # the manifest's min_consumer_version this checker can read
KEY_FILE_SCHEMA_V1 = "kanonik-chain-root-keys/v1"
KEY_FILE_SCHEMA_V2 = "kanonik-chain-root-keys/v2"
KEY_STATUS_RANK = {"active": 0, "retired": 1, "revoked": 2}
DISCLOSURE_RECORD_STATUSES = ("current", "needs_review", "superseded", "retired", "unknown")
DISCLOSURE_ACCESS_STATES = ("active", "revoked", "expired", "unknown")
# The status address in a file is untrusted input: only Kanonik's own public status endpoint is fetched.
DISCLOSURE_STATUS_HOSTS = ("kanonik.ai", "share.kanonik.ai")
_DISCLOSURE_STATUS_PATH = re.compile(r"^/api/v1/public/disclosures/[A-Za-z0-9_-]+/status$")


def _key_status(raw: Any) -> str:
    """A key's status. A missing status is active (the v1 file); a word this checker does not know is treated as
    revoked, so a newer file can never widen trust on an older checker."""
    if raw is None or raw == "":
        return "active"
    return raw if isinstance(raw, str) and raw in KEY_STATUS_RANK else "revoked"


@functools.lru_cache(maxsize=128)
def _spki_of_pem(p: bytes) -> str:
    try:
        from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
            Encoding, PublicFormat, load_pem_public_key,
        )
        der = load_pem_public_key(p).public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    except Exception:  # noqa: BLE001
        return ""
    return hashlib.sha256(der).hexdigest()


def _spki_sha256(pem: Any) -> str:
    """SHA-256 (hex) of the DER SubjectPublicKeyInfo of a PEM public key; empty when it does not parse."""
    p = _coerce_pem(pem)
    return _spki_of_pem(p) if p is not None else ""


def _key_entry(k: dict[str, Any], status: Optional[str] = None) -> Optional[dict[str, Any]]:
    pem = _coerce_pem(k.get("pem"))
    if pem is None:
        return None
    def text(v: Any) -> str:
        return v if isinstance(v, str) else ""  # a value that is not text is no value (verify.mjs reads it the same way)

    return {
        "signing_key_id": text(k.get("signing_key_id")),
        "env": text(k.get("env")).lower(),
        "class": text(k.get("class")),
        "label": text(k.get("label")),
        "seal_required_from": text(k.get("seal_required_from")),
        "pem": pem,
        "sha256_spki_der": _spki_sha256(pem),  # derived from the key; a fingerprint the entry claims is never used
        "status": status if status is not None else _key_status(k.get("status")),
    }


def _consolidate_keys(keys: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Give every entry for the same public key (same SPKI hash) the strongest status any of them has, so a
    revocation cannot be dodged by listing the key twice (a --trusted-keys file repeating a shipped anchor).
    Returns copies; the input is left alone."""
    # Identity comes from the key itself, never from a fingerprint the entry claims for it.
    spkis = [_spki_sha256(k.get("pem")) for k in keys]
    worst: dict[str, int] = {}
    for k, s in zip(keys, spkis):
        if s:
            worst[s] = max(worst.get(s, 0), KEY_STATUS_RANK[_key_status(k.get("status"))])
    names = {v: n for n, v in KEY_STATUS_RANK.items()}
    out = []
    for k, s in zip(keys, spkis):
        e = dict(k)
        e["status"] = names[worst[s]] if s else _key_status(k.get("status"))
        out.append(e)
    return out


def _verify_key_file_continuity(pinned: list[dict[str, Any]], doc: dict[str, Any]) -> tuple[bool, str]:
    """A v2 key file is accepted only when a pinned PRODUCTION key (active or retired, never revoked, never a
    sample or integration key) signed it. continuity = {signed_by: sha256 of that key's SPKI, signed_at, signature};
    the signature is ECDSA P-384 + SHA-384 over the canonical JSON of the whole document with continuity.signature
    removed (so the key list, signer and time are all covered)."""
    cont = doc.get("continuity")
    if not isinstance(cont, dict):
        return False, "the key file carries no continuity signature"
    if _unrepresentable(doc):
        return False, "the key file holds a value this checker cannot read the same way as another checker"
    signed_by = cont.get("signed_by")
    sig_b64 = cont.get("signature")
    if not isinstance(signed_by, str) or not isinstance(sig_b64, str) or not isinstance(cont.get("signed_at"), str):
        return False, "the continuity block is incomplete"
    signer = next((k for k in pinned if k.get("sha256_spki_der") == signed_by), None)
    if signer is None:
        return False, "the continuity signer is not a pinned key"
    if signer.get("env") != "production" or signer.get("class") == "sample":
        return False, "the continuity signer is not a pinned production key"
    if signer.get("status") == "revoked":
        return False, "the continuity signer is revoked"
    try:
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        from cryptography.hazmat.primitives.serialization import load_pem_public_key  # noqa: PLC0415
        body = {k: v for k, v in doc.items() if k != "continuity"}
        body["continuity"] = {k: v for k, v in cont.items() if k != "signature"}
        signed = canonical_marshal(body)
        pub = load_pem_public_key(_coerce_pem(signer.get("pem")) or b"")
        if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP384R1):
            return False, "the continuity signer is not a P-384 key"
        pub.verify(_canonical_b64(sig_b64), signed, ec.ECDSA(hashes.SHA384()))
    except Exception:  # noqa: BLE001
        return False, "the continuity signature does not verify"
    return True, ""


KEY_FILE_MAX_BYTES = 262144
_SIGNED_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", re.ASCII)
_SPKI_HEX = re.compile(r"[0-9a-f]{64}", re.ASCII)


def _revoked_spkis(doc: Any) -> list[str]:
    """The SPKI hashes a key file lists under `revoked_keys`. That field is separate from `keys` on purpose:
    checkers up to 2.7.18 add every key in `keys` that has a PEM and ignore its status, so a revoked key is never
    published there. An entry is {"sha256_spki_der": "<64 lowercase hex>"} (more fields are ignored)."""
    raw = doc.get("revoked_keys") if isinstance(doc, dict) else None
    if not isinstance(raw, list):
        return []
    return [e["sha256_spki_der"] for e in raw if isinstance(e, dict) and isinstance(e.get("sha256_spki_der"), str) and _SPKI_HEX.fullmatch(e["sha256_spki_der"])]


def _apply_revoked(keys: list[dict[str, Any]], doc: Any) -> list[dict[str, Any]]:
    gone = set(_revoked_spkis(doc))
    if not gone:
        return keys
    return [dict(k, status="revoked") if k.get("sha256_spki_der") in gone else k for k in keys]


def merge_key_file(pinned: list[dict[str, Any]], doc: Any, min_signed_at: str = "") -> tuple[list[dict[str, Any]], str, str]:
    """Merge a key file fetched from the well-known address into the pinned set. Returns (keys, mode, note).

    mode "continuity": a v2 file with a valid continuity signature signed no earlier than `min_signed_at` (the floor
        the shipped key file carries, so an older signed file cannot be replayed). It may add keys (including a new
        production key) and move a known key's status forward (active -> retired -> revoked, also through
        `revoked_keys`); it can never move one back.
    mode "rejected": anything else, an unsigned file or a v1 file included. Nothing is taken from it: an unsigned
        file is exactly what a tampered www deploy would serve (a tampered web deploy adding a trusted key).
    The pinned set always wins: nothing here removes a pinned key or changes its public key."""
    pinned = _consolidate_keys([e for e in (_key_entry(k, status=_key_status(k.get("status"))) for k in pinned) if e is not None])
    if not isinstance(doc, dict) or not isinstance(doc.get("keys", []), list):
        return list(pinned), "rejected", "the online key file is not a key file"
    schema = doc.get("schema")
    if schema != KEY_FILE_SCHEMA_V2:
        if schema in (KEY_FILE_SCHEMA_V1, None):
            return list(pinned), "rejected", "the online key file is not signed (no v2 schema): nothing was taken from it"
        return list(pinned), "rejected", f"the online key file names a schema this checker does not read: {schema!r}"
    ok, why = _verify_key_file_continuity(pinned, doc)
    if not ok:
        return list(pinned), "rejected", f"the online key file was not used: {why}"
    if min_signed_at:
        at = doc["continuity"].get("signed_at")
        if not isinstance(at, str) or not _SIGNED_AT.fullmatch(at):
            return list(pinned), "rejected", "the online key file was not used: its signing time is not in the form YYYY-MM-DDTHH:MM:SSZ"
        if at < min_signed_at:
            return list(pinned), "rejected", f"the online key file was not used: it was signed {at}, before {min_signed_at}, the earliest this checker accepts (an old file served again)"
    out = [dict(k) for k in pinned]
    by_spki = {k.get("sha256_spki_der"): k for k in out}
    for raw in doc.get("keys") or []:
        if not isinstance(raw, dict):
            continue
        entry = _key_entry(raw)
        if entry is None or not entry["sha256_spki_der"]:
            continue
        have = by_spki.get(entry["sha256_spki_der"])
        if have is not None:
            if KEY_STATUS_RANK[entry["status"]] > KEY_STATUS_RANK[have["status"]]:
                have["status"] = entry["status"]
            continue
        out.append(entry)
        by_spki[entry["sha256_spki_der"]] = entry
    return _consolidate_keys(_apply_revoked(out, doc)), "continuity", ""


def disclosure_status_url_allowed(url: Any) -> bool:
    """Only https://kanonik.ai or https://share.kanonik.ai, default port, no credentials, the public status path
    and no query: the address comes from the file under test, so it is never fetched anywhere else."""
    if not isinstance(url, str) or not url or re.search(r"[\x00-\x20\x7f\\]", url):
        return False
    try:
        from urllib.parse import urlsplit  # noqa: PLC0415
        u = urlsplit(url)
        return (
            u.scheme == "https"
            and (u.hostname or "") in DISCLOSURE_STATUS_HOSTS
            and u.port is None
            and u.username is None
            and u.password is None
            and not u.query
            and not u.fragment
            and bool(_DISCLOSURE_STATUS_PATH.fullmatch(u.path))
            and u.netloc == (u.hostname or "")
        )
    except Exception:  # noqa: BLE001
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an error: the address was checked, where it points was not."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401, ANN001
        return None


def _urlopen_no_redirect(req: Any, timeout: int = 10) -> Any:
    return urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout)  # noqa: S310


def fetch_disclosure_status(url: Any) -> Any:
    """GET the public status endpoint of a disclosure. Returns the parsed JSON, or None when the address is not
    allowed or the read fails for any reason (the report then says the status is unknown)."""
    if not disclosure_status_url_allowed(url):
        return None
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
        with _urlopen_no_redirect(req) as resp:
            return json.loads(resp.read(65536).decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _unrepresentable(v: Any, depth: int = 0) -> Optional[str]:
    """What in a manifest cannot be put in canonical form the same way in every checker: a number that is not a
    whole number within +-(2^53-1) (JavaScript rounds the rest), an unpaired surrogate (JavaScript replaces it), or
    nesting deep enough to be an attack. verify.mjs applies the same rule, so one file cannot read signed in one
    checker and changed in the other."""
    if depth > 64:
        return "nesting deeper than 64 levels"
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, str):
        return "an unpaired surrogate in a string" if any("\ud800" <= c <= "\udfff" for c in v) else None
    if isinstance(v, (int, float)):
        if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf")) or not v.is_integer()):
            return "a number that is not a whole number"
        return "a number beyond 2^53-1" if abs(v) > 2**53 - 1 else None
    if isinstance(v, list):
        for x in v:
            r = _unrepresentable(x, depth + 1)
            if r:
                return r
        return None
    if isinstance(v, dict):
        for k, x in v.items():
            r = _unrepresentable(k, depth + 1) or _unrepresentable(x, depth + 1)
            if r:
                return r
        return None
    return "a value that is not JSON"


def _disc_fail(check: str, kind: str, message: str) -> CheckResult:
    r = CheckResult(check=check, status="FAIL", count=1)
    r.anomalies.append({"kind": kind, "message": message})
    return r


def check_disclosure_status(requested: bool, response: Any) -> tuple[CheckResult, dict[str, Any]]:
    """Report the current status of the item (display only; it never changes what the signature proves).
    record_status: current | needs_review | superseded | retired | unknown. access_state: active | revoked |
    expired | unknown. The two are never merged. Anything unreadable is unknown, with the integrity result as shown."""
    result = CheckResult(check="disclosure_status", status="PASS", count=1)
    info: dict[str, Any] = {"record_status": "unknown", "access_state": "unknown", "checked": bool(requested), "as_of": ""}
    if not requested:
        result.notes.append("status not checked (offline). Run again with --online to ask Kanonik whether this is still current and still shared.")
        return result, info
    ok = isinstance(response, dict)
    rs = response.get("record_status") if ok else None
    acc = response.get("access_state") if ok else None
    info["record_status"] = rs if isinstance(rs, str) and rs in DISCLOSURE_RECORD_STATUSES else "unknown"
    info["access_state"] = acc if isinstance(acc, str) and acc in DISCLOSURE_ACCESS_STATES else "unknown"
    if ok and isinstance(response.get("as_of"), str):
        info["as_of"] = response["as_of"]
    if info["record_status"] == "current" and info["access_state"] == "active":
        result.notes.append(f"status: current, access active (as of {info['as_of'] or 'now'})")
        return result, info
    result.status = "DEGRADED"
    if info["record_status"] == "unknown" or info["access_state"] == "unknown":
        result.notes.append("status unknown, integrity as shown: the signature result above stands, but whether this is still current and still shared could not be read.")
    if info["record_status"] not in ("current", "unknown"):
        result.notes.append(f"the record is {info['record_status'].replace('_', ' ')}: it was approved when issued and has changed since.")
    if info["access_state"] in ("revoked", "expired"):
        result.notes.append(f"access is {info['access_state']}: this copy was issued legitimately and has since been withdrawn from sharing.")
    return result, info


def run_disclosure_checks(
    doc: Any,
    trusted_keys: Optional[list[dict[str, Any]]] = None,
    status_requested: bool = False,
    status_response: Any = None,
) -> tuple[str, list[CheckResult], dict[str, Any]]:
    """Check one disclosure file. Returns (outcome, checks, status_info). The outcome words are listed above."""
    info: dict[str, Any] = {"record_status": "unknown", "access_state": "unknown", "checked": False, "as_of": ""}
    schema_check = "disclosure_schema_and_version"
    if not isinstance(doc, dict) or not isinstance(doc.get("manifest"), dict) or not isinstance(doc.get("signature"), dict):
        return "MALFORMED", [_disc_fail(schema_check, "disclosure_malformed", "this is not a disclosure file: it needs a manifest and a signature block")], info
    m = doc["manifest"]
    sig = doc["signature"]
    if m.get("schema") != DISCLOSURE_MANIFEST_SCHEMA:
        return "UNKNOWN_SCHEMA", [_disc_fail(schema_check, "disclosure_schema_unknown", f"the manifest schema is {m.get('schema')!r}; this checker reads {DISCLOSURE_MANIFEST_SCHEMA}. Refused, not guessed.")], info
    if sig.get("version") != DISCLOSURE_SIGNATURE_VERSION:
        return "UNKNOWN_SCHEMA", [_disc_fail(schema_check, "disclosure_signature_version_unknown", f"the signature version is {sig.get('version')!r}; this checker reads {DISCLOSURE_SIGNATURE_VERSION}")], info
    minimum = m.get("min_verifier_version")
    cons = m.get("min_consumer_version")
    if isinstance(cons, float) and cons.is_integer():
        cons = int(cons)  # JSON has one number type; verify.mjs reads 1.0 as 1
    if not isinstance(minimum, str) or not minimum or isinstance(cons, bool) or not isinstance(cons, int):
        return "MALFORMED", [_disc_fail(schema_check, "disclosure_version_fields_missing", "the manifest names no minimum checker version or consumer version")], info
    if _version_tuple(minimum) > _version_tuple(VERIFIER_VERSION):
        return "VERIFIER_TOO_OLD", [_disc_fail(schema_check, "disclosure_verifier_too_old", f"the file needs checker {minimum} or later; this is {VERIFIER_VERSION}. Get the current checker from kanonik.ai/verify.")], info
    if cons > DISCLOSURE_CONSUMER_VERSION:
        return "VERIFIER_TOO_OLD", [_disc_fail(schema_check, "disclosure_consumer_too_new", f"the file needs consumer version {cons}; this checker reads {DISCLOSURE_CONSUMER_VERSION}. Get the current checker from kanonik.ai/verify.")], info
    key_id = m.get("key_id")
    publisher = m.get("publisher")
    pub_id = publisher.get("public_id") if isinstance(publisher, dict) else None
    issued = m.get("issued_at")
    digest_stated = sig.get("manifest_sha384")
    if not all(isinstance(x, str) and x for x in (key_id, pub_id, issued, digest_stated)) or not isinstance(sig.get("value"), str):
        return "MALFORMED", [_disc_fail(schema_check, "disclosure_malformed", "the manifest or signature block is missing a field the signature covers (key_id, publisher, issued_at, digest, value)")], info

    bad = _unrepresentable(m)
    if bad:
        return "MALFORMED", [_disc_fail(schema_check, "disclosure_value_unrepresentable", f"the manifest holds {bad}; this checker refuses it rather than read it differently from another checker")], info

    checks: list[CheckResult] = []
    schema_ok = CheckResult(check=schema_check, status="PASS", count=1)
    schema_ok.notes.append(f"{DISCLOSURE_MANIFEST_SCHEMA}, signature {DISCLOSURE_SIGNATURE_VERSION}; the file needs checker {minimum}, this is {VERIFIER_VERSION}")
    checks.append(schema_ok)

    def finish(outcome: str, sig_check: CheckResult) -> tuple[str, list[CheckResult], dict[str, Any]]:
        checks.append(sig_check)
        st, st_info = check_disclosure_status(status_requested, status_response) if outcome.startswith("VERIFIED") else (None, info)
        if st is not None:
            checks.append(st)
        return outcome, checks, st_info

    trusted_keys = _consolidate_keys(trusted_keys or [])
    candidates = [k for k in trusted_keys if k.get("signing_key_id") == key_id]
    if not candidates:
        return finish("UNKNOWN_ISSUER", _disc_fail(
            "disclosure_signature", "disclosure_issuer_unknown",
            f"the file was signed with key {key_id!r}, which this checker does not pin. The file is not shown to be forged: this checker may be older than the key. "
            "Get the current checker from kanonik.ai/verify, or run again with --online.",
        ))

    try:
        digest = hashlib.sha384(canonical_marshal(m)).hexdigest()
    except Exception as e:  # noqa: BLE001
        return finish("MALFORMED", _disc_fail("disclosure_signature", "disclosure_manifest_unreadable", f"the manifest cannot be put in canonical form: {e}"))
    sig_name = "disclosure_signature"
    if digest != digest_stated:
        return finish("BAD_SIGNATURE", _disc_fail(sig_name, "disclosure_manifest_changed", "the manifest is not the one that was signed: its digest differs from the signed digest (changed after signing, or damaged)"))

    try:
        signing_input = canonical_marshal({
            "version": DISCLOSURE_SIGNATURE_VERSION, "manifest_sha384": digest, "publisher_public_id": pub_id,
            "issued_at": issued, "key_id": key_id,
        })
        raw_sig = _canonical_b64(sig["value"])
    except Exception:  # noqa: BLE001
        return finish("BAD_SIGNATURE", _disc_fail(sig_name, "disclosure_signature_unreadable", "the signature is empty or is not canonical base64"))
    try:
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        from cryptography.hazmat.primitives.serialization import load_pem_public_key  # noqa: PLC0415
    except ImportError:
        r = CheckResult(check=sig_name, status="DEGRADED", count=1)
        r.notes.append("the cryptography package is not installed, so the signature was not checked; install requirements.txt and run again.")
        return finish("UNVERIFIED", r)
    matched: Optional[dict[str, Any]] = None
    for k in candidates:
        try:
            pub = load_pem_public_key(_coerce_pem(k.get("pem")) or b"")
            if isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP384R1):
                pub.verify(raw_sig, signing_input, ec.ECDSA(hashes.SHA384()))
                matched = k
                break
        except Exception:  # noqa: BLE001
            continue
    if matched is None:
        return finish("BAD_SIGNATURE", _disc_fail(sig_name, "disclosure_signature_invalid", f"the signature does not verify under any pinned key with id {key_id!r}: signed by another key, or changed after signing"))
    if matched.get("status") == "revoked":
        return finish("KEY_REVOKED", _disc_fail(sig_name, "disclosure_key_revoked", f"the key {key_id!r} that signed this file has been revoked by Kanonik. Do not rely on it."))

    items = m.get("items")
    if not isinstance(items, list) or not items:
        return finish("MALFORMED", _disc_fail(sig_name, "disclosure_items_missing", "the signed manifest carries no items"))
    for i, it in enumerate(items):
        text = it.get("text") if isinstance(it, dict) else None
        try:
            text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest() if isinstance(text, str) else None
        except UnicodeEncodeError:  # a lone surrogate is not text
            text_hash = None
        if text_hash is None or it.get("text_sha256") != text_hash:
            return finish("MALFORMED", _disc_fail(sig_name, "disclosure_item_hash_mismatch", f"item {i}'s stated hash is not the hash of its text"))

    r = CheckResult(check=sig_name, status="PASS", count=len(items))
    env = matched.get("env") or ""
    if matched.get("class") == "sample":
        r.status = "DEGRADED"
        r.notes.append(SAMPLE_KEY_NOTE)
        outcome = "VERIFIED_NON_PRODUCTION"
    elif env == "production":
        outcome = "VERIFIED"
        r.notes.append(f"ECDSA P-384 + SHA-384 signature verified against Kanonik's PINNED PRODUCTION key (id {key_id!r}); issued {issued}")
        if matched.get("status") == "retired":
            r.notes.append("that key is retired: it no longer signs, and a file it signed while active still verifies.")
    else:
        r.status = "DEGRADED"
        outcome = "VERIFIED_NON_PRODUCTION"
        r.notes.append(f"signature verified against a pinned NON-PRODUCTION Kanonik key (env={env or 'dev'}); the file is structurally sound but is NOT attestable to Kanonik's PRODUCTION key. Expected for integration/dev files.")
    r.notes.append("What this shows: Kanonik attested that this text was approved and sealed in the named event, and it is unchanged since. It does not show the text is true, and this checker cannot recompute that event's hash.")
    return finish(outcome, r)


def _clean(v: Any) -> str:
    """Text from a file under test, made safe to print: control, format and line-separator characters are dropped,
    so an escape sequence in the file cannot redraw the verdict above it."""
    import unicodedata  # noqa: PLC0415
    return "".join(c for c in str(v) if unicodedata.category(c) not in ("Cc", "Cf", "Zl", "Zp", "Cs"))


def run_disclosure_mode(path: Path, trusted_keys: Optional[list[dict[str, Any]]], online: bool, online_keys: Optional[dict[str, str]] = None) -> int:
    """Verify one disclosure file and print the report."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        print(f"error: could not read the disclosure file: {e}", file=sys.stderr)
        return 2
    response = None
    if online and isinstance(doc, dict) and isinstance(doc.get("manifest"), dict):
        response = fetch_disclosure_status(doc["manifest"].get("status_url"))
    try:
        outcome, results, status = run_disclosure_checks(doc, trusted_keys, status_requested=online, status_response=response)
    except Exception as e:  # noqa: BLE001
        print(f"error: verifier crashed: {e}", file=sys.stderr)
        return 2
    summary = summarise(results)
    summary["mode"] = "disclosure"
    summary["outcome"] = outcome
    summary["status"] = status
    summary["online_keys"] = online_keys or {"state": "not_requested", "note": ""}
    m = doc.get("manifest") if isinstance(doc, dict) and isinstance(doc.get("manifest"), dict) else {}
    pub = m.get("publisher") if isinstance(m.get("publisher"), dict) else {}
    # What the file says about itself is shown only when the signature held: under any other result it is
    # unverified text from whoever made the file.
    verified = outcome.startswith("VERIFIED")
    summary["disclosure"] = {
        "disclosure_id": m.get("disclosure_id"), "publisher": pub.get("label"), "issued_at": m.get("issued_at"),
        "expires_at": m.get("expires_at"), "check_code": m.get("check_code"),
        "subject": (m.get("subject_ref") or {}).get("title") if isinstance(m.get("subject_ref"), dict) else None,
    } if verified else {}
    print("You can check this file without asking Kanonik. What you still rely on Kanonik for: the pinned signing keys in this checker.", file=sys.stderr)
    print("", file=sys.stderr)
    print(f"Disclosure verification: {outcome}", file=sys.stderr)
    print(f"Checker version: {VERIFIER_VERSION}", file=sys.stderr)
    if verified and pub.get("label"):
        print(f"Published by: {_clean(pub.get('label'))}", file=sys.stderr)
    if verified and m.get("issued_at"):
        print(f"Issued: {_clean(m.get('issued_at'))}", file=sys.stderr)
    line = online_keys_line(online_keys)
    if line:
        print(line, file=sys.stderr)
    print(f"Record status: {status['record_status']}; access: {status['access_state']}", file=sys.stderr)
    print("", file=sys.stderr)
    for r in results:
        marker = {"PASS": "passed ", "FAIL": "failed ", "DEGRADED": "notes  "}.get(r.status, "??? ")
        print(f"[{marker}] {r.check}", file=sys.stderr)
        for note in r.notes:
            print(f"        {_clean(note)}", file=sys.stderr)
        for a in r.anomalies:
            print(f"        - {_clean(a.get('kind', 'anomaly'))}: {_clean(a.get('message', ''))}", file=sys.stderr)
    print(f"\nOverall: {result_word(summary['overall_status'])}", file=sys.stderr)
    _say_json_follows()
    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if summary["overall_status"] == "PASS" else 1


# ---------------------------------------------------------------------------
# Trust feed (`--feed`): a signed kanonik-trust-feed/v1 file a company re-hosts
# ---------------------------------------------------------------------------
#
# The file is {"feed": {...}, "signature": {"version", "feed_sha384", "value"}}. The chain-root key signed the
# canonical JSON of {version: "trust-feed-v1", feed_sha384, publisher_public_id, issued_at, key_id}, built the way
# `disclosure-v1` is; publisher_public_id is feed.publisher.public_id, issued_at and key_id are feed's own. The
# digest and the signing input are re-derived from the feed in the file, the key is picked by feed.key_id from the
# pinned set and nothing the file carries is trusted. Whitespace and key order in a copy do not matter; any changed
# value does. Every object refuses members it does not list (the embedded schema, a copy of
# the published kanonik.ai/schemas/trust-feed/v1.json, checked after the signature).
#
# Outcomes: the `--disclosure` words (VERIFIED, VERIFIED_NON_PRODUCTION, UNKNOWN_ISSUER, BAD_SIGNATURE, KEY_REVOKED,
# UNKNOWN_SCHEMA, VERIFIER_TOO_OLD, MALFORMED) and one more, STALE: the signature is good but this checker's clock
# is past valid_until. A file over 1 MiB is refused before it is parsed (MALFORMED). Air-gapped unless --online,
# which fetches the live feed only from https://share.kanonik.ai/t/{slug}/feed.json and lists the differences.
FEED_SCHEMA = "kanonik-trust-feed/v1"
FEED_SIGNATURE_VERSION = "trust-feed-v1"
FEED_CONSUMER_VERSION = 1  # the feed's min_consumer_version this checker can read
FEED_MAX_BYTES = 1048576  # 1 MiB, refused before parsing
FEED_HOSTS = ("share.kanonik.ai",)
_FEED_PATH = re.compile(r"/t/[a-z0-9](?:[a-z0-9]|-(?!-)){1,38}[a-z0-9]/feed\.json")
FEED_NOT_PUBLISHED = "the company no longer publishes this page"
FEED_STALE_MESSAGE = "This copy was correct on {issued_at}. It is too old to rely on; fetch the current one."
_FEED_SCHEMA_JSON = r'''{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://kanonik.ai/schemas/trust-feed/v1.json","type":"object","additionalProperties":false,"required":["feed","signature"],"properties":{"feed":{"$ref":"#/$defs/feed"},"signature":{"$ref":"#/$defs/signature"}},"$defs":{"slug":{"type":"string","pattern":"^[a-z0-9](?:[a-z0-9]|-(?!-)){1,38}[a-z0-9]$"},"publicId":{"type":"string","pattern":"^[A-Za-z0-9_-]{21}[AQgw]$"},"checkCode":{"type":"string","pattern":"^[2-9A-HJKMNP-TW-Z]{4}(-[2-9A-HJKMNP-TW-Z]{4}){3}$"},"sha384":{"type":"string","pattern":"^[0-9a-f]{96}$"},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"utcTime":{"type":"string","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"},"utcDate":{"type":"string","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},"httpsUrl":{"type":"string","maxLength":300,"pattern":"^https://[a-z0-9.-]+/"},"plainText":{"type":"string","minLength":1},"signature":{"type":"object","additionalProperties":false,"required":["version","feed_sha384","value"],"properties":{"version":{"const":"trust-feed-v1"},"feed_sha384":{"$ref":"#/$defs/sha384"},"value":{"type":"string","minLength":1,"maxLength":200,"pattern":"^[A-Za-z0-9+/]+={0,2}$"}}},"feed":{"type":"object","additionalProperties":false,"required":["schema","feed_url","page_url","publisher","issued_at","valid_until","key_id","min_consumer_version","min_verifier_version","profile","items","statement"],"properties":{"schema":{"const":"kanonik-trust-feed/v1"},"feed_url":{"allOf":[{"$ref":"#/$defs/httpsUrl"}],"pattern":"^https://[a-z0-9.-]+/t/[a-z0-9][a-z0-9-]{1,38}[a-z0-9]/feed\\.json$"},"page_url":{"allOf":[{"$ref":"#/$defs/httpsUrl"}],"pattern":"^https://[a-z0-9.-]+/t/[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$"},"publisher":{"type":"object","additionalProperties":false,"required":["public_id","label"],"properties":{"public_id":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[a-z0-9-]+$"},"label":{"allOf":[{"$ref":"#/$defs/plainText"}],"maxLength":200}}},"issued_at":{"$ref":"#/$defs/utcTime"},"valid_until":{"$ref":"#/$defs/utcTime"},"key_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._/-]+$"},"min_consumer_version":{"type":"integer","minimum":1},"min_verifier_version":{"type":"string","pattern":"^[0-9]+\\.[0-9]+\\.[0-9]+$"},"profile":{"$ref":"#/$defs/profile"},"items":{"type":"array","maxItems":40,"items":{"$ref":"#/$defs/item"}},"statement":{"allOf":[{"$ref":"#/$defs/plainText"}],"maxLength":600}}},"profile":{"type":"object","additionalProperties":false,"required":["public_id","manifest_sha384","disclosure_url","legal_name","display_name","security_contact","proved_domain"],"properties":{"public_id":{"$ref":"#/$defs/publicId"},"manifest_sha384":{"$ref":"#/$defs/sha384"},"disclosure_url":{"allOf":[{"$ref":"#/$defs/httpsUrl"}],"pattern":"^https://[a-z0-9.-]+/api/v1/public/disclosures/[A-Za-z0-9_-]{21}[AQgw]$"},"legal_name":{"allOf":[{"$ref":"#/$defs/plainText"}],"maxLength":200},"display_name":{"allOf":[{"$ref":"#/$defs/plainText"}],"maxLength":200},"intro":{"allOf":[{"$ref":"#/$defs/plainText"}],"maxLength":400},"security_contact":{"type":"string","maxLength":254,"pattern":"^[^@\\s<>\"]+@[a-z0-9.-]+\\.[a-z]{2,}$"},"proved_domain":{"type":"string","maxLength":253,"pattern":"^[a-z0-9.-]+\\.[a-z]{2,}$"}}},"document":{"type":"object","additionalProperties":false,"required":["type","issuer","issue_date","valid_until"],"properties":{"type":{"enum":["pentest_letter","pci_aoc","insurance_certificate"]},"issuer":{"allOf":[{"$ref":"#/$defs/plainText"}],"maxLength":200},"issue_date":{"$ref":"#/$defs/utcDate"},"valid_until":{"$ref":"#/$defs/utcDate"},"file_sha256":{"$ref":"#/$defs/sha256"}}},"item":{"type":"object","additionalProperties":false,"required":["public_id","family","section","title","access","record_status","listed_since","listed_until","check_code","check_url","status_url"],"properties":{"public_id":{"$ref":"#/$defs/publicId"},"family":{"enum":["answer_set","policy","procedure","standing_summary","subprocessor_list","third_party_document"]},"section":{"enum":["at_a_glance","answers","policies","standing","subprocessors","documents"]},"title":{"allOf":[{"$ref":"#/$defs/plainText"}],"maxLength":200},"version":{"type":"string","minLength":1,"maxLength":32},"access":{"enum":["open","on_request"]},"record_status":{"enum":["current","needs_review"]},"approved_on":{"$ref":"#/$defs/utcDate"},"approved_by_titles":{"type":"array","minItems":1,"maxItems":5,"items":{"allOf":[{"$ref":"#/$defs/plainText"}],"maxLength":100}},"review_due":{"$ref":"#/$defs/utcDate"},"listed_since":{"$ref":"#/$defs/utcTime"},"listed_until":{"$ref":"#/$defs/utcTime"},"check_code":{"$ref":"#/$defs/checkCode"},"check_url":{"type":"string","pattern":"^https://[a-z0-9.-]+/verify\\?code=[2-9A-HJKMNP-TW-Z]{4}(-[2-9A-HJKMNP-TW-Z]{4}){3}$"},"status_url":{"type":"string","pattern":"^https://[a-z0-9.-]+/api/v1/public/disclosures/[A-Za-z0-9_-]{21}[AQgw]/status$"},"manifest_sha384":{"$ref":"#/$defs/sha384"},"disclosure_url":{"type":"string","pattern":"^https://[a-z0-9.-]+/api/v1/public/disclosures/[A-Za-z0-9_-]{21}[AQgw]$"},"item_url":{"type":"string","pattern":"^https://[a-z0-9.-]+/d/[A-Za-z0-9_-]{21}[AQgw]$"},"request_url":{"type":"string","pattern":"^https://[a-z0-9.-]+/t/[a-z0-9][a-z0-9-]{1,38}[a-z0-9]/request$"},"nda_required":{"type":"boolean"},"document":{"$ref":"#/$defs/document"}},"allOf":[{"if":{"properties":{"access":{"const":"open"}}},"then":{"required":["manifest_sha384","disclosure_url","item_url"],"not":{"anyOf":[{"required":["request_url"]},{"required":["nda_required"]}]}}},{"if":{"properties":{"access":{"const":"on_request"}}},"then":{"required":["request_url","nda_required"],"not":{"anyOf":[{"required":["manifest_sha384"]},{"required":["disclosure_url"]},{"required":["item_url"]},{"properties":{"document":{"required":["file_sha256"]}},"required":["document"]}]}}},{"if":{"properties":{"family":{"const":"third_party_document"}}},"then":{"required":["document"],"properties":{"section":{"const":"documents"}}},"else":{"not":{"required":["document"]}}},{"if":{"properties":{"section":{"const":"at_a_glance"}}},"then":{"properties":{"family":{"const":"answer_set"},"access":{"const":"open"}}}}]}}}'''
_FEED_SCHEMA: dict[str, Any] = json.loads(_FEED_SCHEMA_JSON)
_UTC_TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z", re.ASCII)


def _utc_seconds(s: Any) -> Optional[int]:
    """Epoch seconds of a YYYY-MM-DDTHH:MM:SSZ time, or None when it is not a real instant (verify.mjs agrees)."""
    m = _UTC_TIME.fullmatch(s) if isinstance(s, str) else None
    if m is None or int(m.group(1)) < 1000:
        return None
    try:
        return int(datetime(*(int(x) for x in m.groups()), tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


@functools.lru_cache(maxsize=256)
def _feed_regex(pattern: str) -> Any:
    # `\s` is spelled out so the two checkers read it alike (JavaScript's covers more characters), and a
    # trailing `$` means the end of the text, not before a final newline.
    p = pattern.replace("\\s", " \\t\\n\\r\\f\\v")
    return re.compile(p[:-1] + "\\Z" if p.endswith("$") and not p.endswith("\\$") else p)


def _schema_json_type(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int) or (isinstance(v, float) and v.is_integer()):
        return "integer"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return "other"


def _schema_check(node: dict[str, Any], v: Any, path: str, errs: list[str], limit: int = 5) -> None:
    """A small JSON Schema reader for exactly the keywords the trust feed schema uses. Appends what is wrong."""
    if len(errs) >= limit:
        return
    if "$ref" in node:
        target: Any = _FEED_SCHEMA
        for part in node["$ref"].removeprefix("#/").split("/"):
            target = target[part]
        _schema_check(target, v, path, errs, limit)
    kind = _schema_json_type(v)
    t = node.get("type")
    if t is not None and not (kind == t or (t == "number" and kind == "integer")):
        errs.append(f"{path or '/'}: expected {t}, found {kind}")
        return
    if "const" in node and (kind != _schema_json_type(node["const"]) or v != node["const"]):
        errs.append(f"{path or '/'}: not the expected value")
    if "enum" in node and not any(kind == _schema_json_type(e) and v == e for e in node["enum"]):
        errs.append(f"{path or '/'}: not one of the allowed values")
    if kind == "string":
        if "pattern" in node and _feed_regex(node["pattern"]).search(v) is None:
            errs.append(f"{path or '/'}: not in the required form")
        if "minLength" in node and len(v) < node["minLength"]:
            errs.append(f"{path or '/'}: too short")
        if "maxLength" in node and len(v) > node["maxLength"]:
            errs.append(f"{path or '/'}: too long")
    if kind == "integer" and "minimum" in node and v < node["minimum"]:
        errs.append(f"{path or '/'}: below the minimum")
    if kind == "array":
        if "minItems" in node and len(v) < node["minItems"]:
            errs.append(f"{path or '/'}: too few entries")
        if "maxItems" in node and len(v) > node["maxItems"]:
            errs.append(f"{path or '/'}: too many entries")
        if "items" in node:
            for i, x in enumerate(v):
                _schema_check(node["items"], x, f"{path}/{i}", errs, limit)
    if kind == "object":
        props = node.get("properties", {})
        for r in node.get("required", []):
            if r not in v:
                errs.append(f"{path or '/'}: the member {r!r} is missing")
        if node.get("additionalProperties") is False:
            for k in v:
                if k not in props:
                    errs.append(f"{path or '/'}: the member {k!r} is not part of this format")
        for k, sub in props.items():
            if k in v:
                _schema_check(sub, v[k], f"{path}/{k}", errs, limit)
    for sub in node.get("allOf", []):
        _schema_check(sub, v, path, errs, limit)
    if "anyOf" in node and not any(not _schema_errors(sub, v) for sub in node["anyOf"]):
        errs.append(f"{path or '/'}: matches none of the allowed shapes")
    if "not" in node and not _schema_errors(node["not"], v):
        errs.append(f"{path or '/'}: carries a member this kind of line must not carry")
    if "if" in node:
        branch = node.get("then") if not _schema_errors(node["if"], v) else node.get("else")
        if branch is not None:
            _schema_check(branch, v, path, errs, limit)


def _schema_errors(node: dict[str, Any], v: Any, path: str = "") -> list[str]:
    errs: list[str] = []
    _schema_check(node, v, path, errs)
    return errs


def feed_shape_errors(feed: Any) -> list[str]:
    """What is wrong with a feed body against the embedded kanonik-trust-feed/v1 schema (empty when nothing)."""
    return _schema_errors(_FEED_SCHEMA["$defs"]["feed"], feed, "feed")


def _now() -> float:
    return datetime.now(timezone.utc).timestamp()


def _age_words(seconds: int) -> str:
    s = max(0, int(seconds))
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d} day{'s' if d != 1 else ''} {h} hour{'s' if h != 1 else ''}"
    if h:
        return f"{h} hour{'s' if h != 1 else ''} {m} minute{'s' if m != 1 else ''}"
    return f"{m} minute{'s' if m != 1 else ''}"


def feed_url_allowed(url: Any) -> bool:
    """Only https://share.kanonik.ai/t/{slug}/feed.json, default port, no credentials, no query: the address comes
    from the file under test, so it is never fetched anywhere else."""
    if not isinstance(url, str) or not url or re.search(r"[\x00-\x20\x7f\\]", url):
        return False
    try:
        from urllib.parse import urlsplit  # noqa: PLC0415
        u = urlsplit(url)
        return (
            u.scheme == "https"
            and (u.hostname or "") in FEED_HOSTS
            and u.port is None
            and u.username is None
            and u.password is None
            and not u.query
            and not u.fragment
            and _FEED_PATH.fullmatch(u.path) is not None
            and u.netloc == (u.hostname or "")
            and "?" not in url
            and "#" not in url
        )
    except Exception:  # noqa: BLE001
        return False


def fetch_live_feed(url: Any) -> dict[str, Any]:
    """GET the live feed. Returns {"state": ...}: "ok" (with "doc", the parsed file), "not_found" (the reply for a
    page that is not published), "refused" (the address is not allowed; nothing was fetched), or "error"."""
    if not feed_url_allowed(url):
        return {"state": "refused"}
    import urllib.error  # noqa: PLC0415
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
        with _urlopen_no_redirect(req) as resp:
            raw = resp.read(FEED_MAX_BYTES + 1)
    except urllib.error.HTTPError as e:
        return {"state": "not_found" if e.code == 404 else "error"}
    except Exception:  # noqa: BLE001
        return {"state": "error"}
    if len(raw) > FEED_MAX_BYTES:
        return {"state": "error", "reason": "too_large"}
    try:
        return {"state": "ok", "doc": json.loads(raw.decode("utf-8"))}
    except Exception:  # noqa: BLE001
        return {"state": "error", "reason": "not_json"}


def _feed_fail(check: str, kind: str, message: str) -> CheckResult:
    return _disc_fail(check, kind, message)


def feed_item_rows(feed: dict[str, Any]) -> list[dict[str, Any]]:
    """Each listed item's code and status words exactly as the copy states them."""
    rows = []
    for it in feed.get("items") or []:
        if not isinstance(it, dict):
            continue
        rows.append({k: it[k] for k in ("public_id", "title", "access", "record_status", "version", "check_code", "review_due", "listed_until") if k in it})
    return rows


def run_feed_checks(
    doc: Any,
    trusted_keys: Optional[list[dict[str, Any]]] = None,
    now: Optional[float] = None,
) -> tuple[str, list[CheckResult], dict[str, Any]]:
    """Check one trust feed file. Returns (outcome, checks, info). `now` is the checker's clock in epoch seconds
    (tests inject it). info is filled only when the signature held."""
    info: dict[str, Any] = {}
    schema_check = "feed_schema_and_version"
    if not isinstance(doc, dict) or not isinstance(doc.get("feed"), dict) or not isinstance(doc.get("signature"), dict):
        return "MALFORMED", [_feed_fail(schema_check, "feed_malformed", "this is not a trust feed file: it needs a feed and a signature block")], info
    extra = sorted(k for k in doc if k not in ("feed", "signature"))
    if extra:
        return "MALFORMED", [_feed_fail(schema_check, "feed_unknown_member", "the file has a member outside feed and signature, which this format does not allow")], info
    f = doc["feed"]
    sig = doc["signature"]
    if f.get("schema") != FEED_SCHEMA:
        return "UNKNOWN_SCHEMA", [_feed_fail(schema_check, "feed_schema_unknown", f"the feed schema is {f.get('schema')!r}; this checker reads {FEED_SCHEMA}. Refused, not guessed.")], info
    if sig.get("version") != FEED_SIGNATURE_VERSION:
        return "UNKNOWN_SCHEMA", [_feed_fail(schema_check, "feed_signature_version_unknown", f"the signature version is {sig.get('version')!r}; this checker reads {FEED_SIGNATURE_VERSION}")], info
    minimum = f.get("min_verifier_version")
    cons = f.get("min_consumer_version")
    if isinstance(cons, float) and cons.is_integer():
        cons = int(cons)  # JSON has one number type; verify.mjs reads 1.0 as 1
    if not isinstance(minimum, str) or not minimum or isinstance(cons, bool) or not isinstance(cons, int):
        return "MALFORMED", [_feed_fail(schema_check, "feed_version_fields_missing", "the feed names no minimum checker version or consumer version")], info
    if _version_tuple(minimum) > _version_tuple(VERIFIER_VERSION):
        return "VERIFIER_TOO_OLD", [_feed_fail(schema_check, "feed_verifier_too_old", f"the file needs checker {minimum} or later; this is {VERIFIER_VERSION}. Get the current checker from kanonik.ai/verify.")], info
    if cons > FEED_CONSUMER_VERSION:
        return "VERIFIER_TOO_OLD", [_feed_fail(schema_check, "feed_consumer_too_new", f"the file needs consumer version {cons}; this checker reads {FEED_CONSUMER_VERSION}. Get the current checker from kanonik.ai/verify.")], info
    key_id = f.get("key_id")
    publisher = f.get("publisher")
    pub_id = publisher.get("public_id") if isinstance(publisher, dict) else None
    issued = f.get("issued_at")
    digest_stated = sig.get("feed_sha384")
    if not all(isinstance(x, str) and x for x in (key_id, pub_id, issued, digest_stated)) or not isinstance(sig.get("value"), str):
        return "MALFORMED", [_feed_fail(schema_check, "feed_malformed", "the feed or signature block is missing a field the signature covers (key_id, publisher, issued_at, digest, value)")], info
    if any(k not in ("version", "feed_sha384", "value") for k in sig):
        return "MALFORMED", [_feed_fail(schema_check, "feed_unknown_member", "the signature block has a member this format does not allow")], info
    bad = _unrepresentable(f)
    if bad:
        return "MALFORMED", [_feed_fail(schema_check, "feed_value_unrepresentable", f"the feed holds {bad}; this checker refuses it rather than read it differently from another checker")], info

    checks: list[CheckResult] = []
    schema_ok = CheckResult(check=schema_check, status="PASS", count=1)
    schema_ok.notes.append(f"{FEED_SCHEMA}, signature {FEED_SIGNATURE_VERSION}; the file needs checker {minimum}, this is {VERIFIER_VERSION}")
    checks.append(schema_ok)

    def finish(outcome: str, sig_check: CheckResult) -> tuple[str, list[CheckResult], dict[str, Any]]:
        checks.append(sig_check)
        return outcome, checks, info

    sig_name = "feed_signature"
    trusted_keys = _consolidate_keys(trusted_keys or [])
    candidates = [k for k in trusted_keys if k.get("signing_key_id") == key_id]
    if not candidates:
        return finish("UNKNOWN_ISSUER", _feed_fail(
            sig_name, "feed_issuer_unknown",
            f"the file was signed with key {key_id!r}, which this checker does not pin. The file is not shown to be forged: this checker may be older than the key. "
            "Get the current checker from kanonik.ai/verify, or run again with --online.",
        ))
    try:
        digest = hashlib.sha384(canonical_marshal(f)).hexdigest()
    except Exception as e:  # noqa: BLE001
        return finish("MALFORMED", _feed_fail(sig_name, "feed_unreadable", f"the feed cannot be put in canonical form: {e}"))
    if digest != digest_stated:
        return finish("BAD_SIGNATURE", _feed_fail(sig_name, "feed_changed", "the feed is not the one that was signed: its digest differs from the signed digest (changed after signing, or damaged)"))
    try:
        signing_input = canonical_marshal({
            "version": FEED_SIGNATURE_VERSION, "feed_sha384": digest, "publisher_public_id": pub_id,
            "issued_at": issued, "key_id": key_id,
        })
        raw_sig = _canonical_b64(sig["value"])
    except Exception:  # noqa: BLE001
        return finish("BAD_SIGNATURE", _feed_fail(sig_name, "feed_signature_unreadable", "the signature is empty or is not canonical base64"))
    try:
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        from cryptography.hazmat.primitives.serialization import load_pem_public_key  # noqa: PLC0415
    except ImportError:
        r = CheckResult(check=sig_name, status="DEGRADED", count=1)
        r.notes.append("the cryptography package is not installed, so the signature was not checked; install requirements.txt and run again.")
        return finish("UNVERIFIED", r)
    matched: Optional[dict[str, Any]] = None
    for k in candidates:
        try:
            pub = load_pem_public_key(_coerce_pem(k.get("pem")) or b"")
            if isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP384R1):
                pub.verify(raw_sig, signing_input, ec.ECDSA(hashes.SHA384()))
                matched = k
                break
        except Exception:  # noqa: BLE001
            continue
    if matched is None:
        return finish("BAD_SIGNATURE", _feed_fail(sig_name, "feed_signature_invalid", f"the signature does not verify under any pinned key with id {key_id!r}: signed by another key, or changed after signing"))
    if matched.get("status") == "revoked":
        return finish("KEY_REVOKED", _feed_fail(sig_name, "feed_key_revoked", f"the key {key_id!r} that signed this file has been revoked by Kanonik. Do not rely on it."))

    r = CheckResult(check=sig_name, status="PASS", count=1)
    env = matched.get("env") or ""
    if matched.get("class") == "sample":
        r.status = "DEGRADED"
        r.notes.append(SAMPLE_KEY_NOTE)
        outcome = "VERIFIED_NON_PRODUCTION"
    elif env == "production":
        outcome = "VERIFIED"
        r.notes.append(f"ECDSA P-384 + SHA-384 signature verified against Kanonik's PINNED PRODUCTION key (id {key_id!r}); issued {issued}")
        if matched.get("status") == "retired":
            r.notes.append("that key is retired: it no longer signs, and a file it signed while active still verifies.")
    else:
        r.status = "DEGRADED"
        outcome = "VERIFIED_NON_PRODUCTION"
        r.notes.append(f"signature verified against a pinned NON-PRODUCTION Kanonik key (env={env or 'dev'}); the file is structurally sound but is NOT attestable to Kanonik's PRODUCTION key. Expected for integration/dev files.")
    r.notes.append("What this shows: Kanonik attested this is what the company's public trust page listed when it was issued, and it is unchanged since. It does not show any listed text is true, and it says nothing about the page now.")
    checks.append(r)

    shape = CheckResult(check="feed_shape", status="PASS", count=len(f.get("items") or []))
    errs = feed_shape_errors(f)
    issued_s, valid_s = _utc_seconds(issued), _utc_seconds(f.get("valid_until"))
    if not errs and (issued_s is None or valid_s is None):
        errs = ["feed: issued_at or valid_until is not a real time"]
    if not errs and valid_s is not None and issued_s is not None and valid_s < issued_s:
        errs = ["feed: valid_until is before issued_at"]
    if errs:
        shape.status = "FAIL"
        shape.anomalies.append({"kind": "feed_shape_invalid", "message": "the signed feed does not match the format " + FEED_SCHEMA + ": " + "; ".join(errs)})
        checks.append(shape)
        return "MALFORMED", checks, info
    shape.notes.append(f"{len(f['items'])} item(s), every member is one the format lists")
    checks.append(shape)

    at = _now() if now is None else now
    age = max(0, int(at - issued_s))
    info.update({
        "publisher": publisher.get("label"), "publisher_public_id": pub_id, "proved_domain": (f.get("profile") or {}).get("proved_domain"), "issued_at": issued, "valid_until": f["valid_until"],
        "age_seconds": age, "feed_url": f.get("feed_url"), "feed_sha384": digest, "key_class": "production" if outcome == "VERIFIED" else "non_production",
        "items": feed_item_rows(f),
    })
    fresh = CheckResult(check="feed_freshness", status="PASS", count=1)
    if at > valid_s:
        fresh.status = "FAIL"
        fresh.anomalies.append({"kind": "feed_stale", "message": FEED_STALE_MESSAGE.format(issued_at=issued)})
        checks.append(fresh)
        info["stale"] = True
        return "STALE", checks, info
    fresh.notes.append(f"copy age {_age_words(age)}; good until {f['valid_until']}")
    checks.append(fresh)
    info["stale"] = False
    return outcome, checks, info


def feed_signature_held(outcome: str) -> bool:
    return outcome.startswith("VERIFIED") or outcome == "STALE"


def diff_feed_items(old: list[dict[str, Any]], new: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Differences by item (public_id) between a copy and the live feed: added, removed, status changed (and
    version changed). Both lists come from feeds whose signatures held."""
    o = {r["public_id"]: r for r in old}
    n = {r["public_id"]: r for r in new}
    out: dict[str, list[dict[str, Any]]] = {"added": [], "removed": [], "status_changed": [], "version_changed": []}
    for pid in sorted(n):
        if pid not in o:
            out["added"].append({"public_id": pid, "title": n[pid].get("title"), "record_status": n[pid].get("record_status")})
    for pid in sorted(o):
        if pid not in n:
            out["removed"].append({"public_id": pid, "title": o[pid].get("title"), "record_status": o[pid].get("record_status")})
            continue
        for key, bucket in (("record_status", "status_changed"), ("version", "version_changed")):
            if o[pid].get(key) != n[pid].get(key):
                out[bucket].append({"public_id": pid, "title": n[pid].get("title"), "from": o[pid].get(key), "to": n[pid].get(key)})
    return out


def feed_lists_manifest(feed: dict[str, Any], digest: str) -> str:
    """Where a signed manifest digest is listed in a feed: '' (not listed), 'profile' or the item's public id."""
    if isinstance(feed.get("profile"), dict) and feed["profile"].get("manifest_sha384") == digest:
        return "profile"
    for it in feed.get("items") or []:
        if isinstance(it, dict) and it.get("manifest_sha384") == digest:
            return str(it.get("public_id"))
    return ""


def verify_feed(
    doc: Any,
    trusted_keys: Optional[list[dict[str, Any]]],
    now: Optional[float] = None,
    live: Optional[dict[str, Any]] = None,
    disclosure: Any = None,
    disclosure_given: bool = False,
) -> tuple[str, list[CheckResult], dict[str, Any]]:
    """The whole feed check: the copy, then (when `live` is given) the live feed and the differences, then (when
    `disclosure_given`) whether that item's signed manifest digest is listed in the feed. Returns (outcome, checks,
    extra) where extra holds the pieces the report prints."""
    at = _now() if now is None else now
    outcome, checks, info = run_feed_checks(doc, trusted_keys, at)
    extra: dict[str, Any] = {"info": info, "online": {"state": "not_requested"}, "disclosure": {"given": False}}
    if live is not None:
        on = CheckResult(check="feed_online", status="PASS", count=1)
        state = live.get("state")
        extra["online"] = {"state": state}
        if state == "ok":
            lo, lchecks, linfo = run_feed_checks(live.get("doc"), trusted_keys, at)
            extra["online"].update({"live_outcome": lo, "live_checks": [asdict(c) for c in lchecks], "live_info": linfo})
            if not feed_signature_held(lo):
                on.status = "DEGRADED"
                on.notes.append(f"the live file did not check out ({lo}), so no differences are listed. Do not rely on it.")
            elif not feed_signature_held(outcome):
                on.status = "DEGRADED"
                on.notes.append("the copy's signature did not hold, so it is not compared with the live file.")
            else:
                d = diff_feed_items(info["items"], linfo["items"])
                extra["online"]["diff"] = d
                if lo == "STALE":
                    on.status = "DEGRADED"
                    on.notes.append(f"the live file is itself past its valid_until ({linfo['valid_until']}); fetch it again later.")
                if info.get("publisher_public_id") != linfo.get("publisher_public_id"):
                    on.status = "DEGRADED"
                    on.notes.append("the live file names a different publisher id than this copy.")
                if not any(d.values()):
                    on.notes.append("the live feed lists the same items with the same status words as this copy.")
                else:
                    on.status = "DEGRADED"
                    for it in d["added"]:
                        on.notes.append(f"added since this copy: {it['title']} ({it['public_id']})")
                    for it in d["removed"]:
                        on.notes.append(f"removed since this copy: {it['title']} ({it['public_id']}). Stop showing it.")
                    for it in d["status_changed"]:
                        on.notes.append(f"status changed: {it['title']} ({it['public_id']}): {it['from']} -> {it['to']}")
                    for it in d["version_changed"]:
                        on.notes.append(f"version changed: {it['title']} ({it['public_id']}): {it['from']} -> {it['to']}")
        elif state == "not_found":
            on.status = "DEGRADED"
            on.notes.append(FEED_NOT_PUBLISHED)
        elif state == "refused":
            on.status = "DEGRADED"
            on.notes.append("the feed address in this file is not https://share.kanonik.ai/t/{slug}/feed.json, so it was not fetched.")
        else:
            on.status = "DEGRADED"
            on.notes.append("the live feed could not be read; nothing is compared. The result above is for the copy only.")
        checks.append(on)
    if disclosure_given:
        dc = CheckResult(check="feed_lists_disclosure", status="PASS", count=1)
        d_outcome, _d_checks, _ = run_disclosure_checks(disclosure, trusted_keys)
        extra["disclosure"] = {"given": True, "outcome": d_outcome, "listed": ""}
        if not d_outcome.startswith("VERIFIED"):
            dc.status = "FAIL"
            dc.anomalies.append({"kind": "disclosure_not_confirmed", "message": f"the item file does not verify on its own ({d_outcome}), so it cannot be confirmed as listed in the feed"})
        elif not feed_signature_held(outcome):
            dc.status = "FAIL"
            dc.anomalies.append({"kind": "feed_not_confirmed", "message": f"the feed does not verify ({outcome}), so the item cannot be confirmed as listed in it"})
        else:
            digest = hashlib.sha384(canonical_marshal(disclosure["manifest"])).hexdigest()
            where = feed_lists_manifest(doc["feed"], digest)
            extra["disclosure"].update({"manifest_sha384": digest, "listed": where})
            if where:
                dc.notes.append("the item's signed manifest digest is listed in the feed" + (" (the page profile)" if where == "profile" else f" (item {where})"))
            else:
                dc.status = "FAIL"
                dc.anomalies.append({"kind": "disclosure_not_in_feed", "message": "this item's signed manifest digest is not listed in the feed. An on-request line lists no digest, by design; an open line that is missing was not published on this page."})
        checks.append(dc)
    return outcome, checks, extra


def _read_capped(path: Path) -> tuple[Optional[bytes], str]:
    """The file's bytes, or (None, reason). A file over 1 MiB is refused before it is parsed."""
    try:
        if path.stat().st_size > FEED_MAX_BYTES:
            return None, "too_large"
        with path.open("rb") as fh:
            raw = fh.read(FEED_MAX_BYTES + 1)
    except OSError as e:
        return None, f"unreadable: {e}"
    return (None, "too_large") if len(raw) > FEED_MAX_BYTES else (raw, "")


def parse_feed_bytes(raw: bytes) -> tuple[Any, Optional[tuple[str, list[CheckResult]]]]:
    """Parse a feed file's bytes. Returns (doc, None), or (None, (outcome, checks)) when it is too big or not JSON."""
    if len(raw) > FEED_MAX_BYTES:
        return None, ("MALFORMED", [_feed_fail("feed_schema_and_version", "feed_too_large", f"the file is larger than {FEED_MAX_BYTES} bytes (1 MiB); this checker refuses it before reading it")])
    def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        # A member named twice would be read as the first by one parser and as the last by another: the copy is refused,
        # so what the signature covers is the only thing there is to read (nothing may be added to a copy).
        d = dict(pairs)
        if len(d) != len(pairs):
            raise ValueError("duplicate key")
        return d

    try:
        # utf-8-sig: a byte-order mark (a copy saved by a Windows editor) is not part of the JSON, as in the page and in Node.
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_no_duplicate_keys), None
    except Exception:  # noqa: BLE001
        return None, ("MALFORMED", [_feed_fail("feed_schema_and_version", "feed_malformed", "this is not a trust feed file: it is not JSON, or it names a member twice")])


def run_feed_mode(
    path: Path,
    trusted_keys: Optional[list[dict[str, Any]]],
    online: bool,
    online_keys: Optional[dict[str, str]] = None,
    disclosure_path: Optional[Path] = None,
    now: Optional[float] = None,
) -> int:
    """Verify one trust feed file and print the report."""
    raw, why = _read_capped(path)
    if raw is None and why != "too_large":
        print(f"error: could not read the feed file: {why}", file=sys.stderr)
        return 2
    doc, early = parse_feed_bytes(raw if raw is not None else b"\0" * (FEED_MAX_BYTES + 1))
    disclosure: Any = None
    if disclosure_path is not None:
        try:
            disclosure = json.loads(disclosure_path.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            print(f"error: could not read the disclosure file: {e}", file=sys.stderr)
            return 2
    try:
        if early is not None:
            outcome, results, extra = early[0], early[1], {"info": {}, "online": {"state": "not_requested"}, "disclosure": {"given": False}}
        else:
            live = None
            if online:
                url = doc["feed"].get("feed_url") if isinstance(doc, dict) and isinstance(doc.get("feed"), dict) else None
                live = fetch_live_feed(url)
            outcome, results, extra = verify_feed(doc, trusted_keys, now, live, disclosure, disclosure_path is not None)
    except Exception as e:  # noqa: BLE001
        print(f"error: verifier crashed: {e}", file=sys.stderr)
        return 2
    summary = summarise(results)
    info = extra["info"]
    summary["mode"] = "feed"
    summary["outcome"] = outcome
    summary["online_keys"] = online_keys or {"state": "not_requested", "note": ""}
    summary["online"] = {k: v for k, v in extra["online"].items() if k not in ("live_checks",)}
    summary["disclosure"] = extra["disclosure"]
    # What the file says about itself is shown only when the signature held: otherwise it is text from whoever made the file.
    summary["feed"] = dict(info) if feed_signature_held(outcome) else {}
    print("You can check this file without asking Kanonik. What you still rely on Kanonik for: the pinned signing keys in this checker.", file=sys.stderr)
    print("", file=sys.stderr)
    print(f"Trust feed verification: {outcome}", file=sys.stderr)
    print(f"Checker version: {VERIFIER_VERSION}", file=sys.stderr)
    if outcome == "STALE":
        print(FEED_STALE_MESSAGE.format(issued_at=_clean(info["issued_at"])), file=sys.stderr)
    if feed_signature_held(outcome):
        if info.get("publisher"):
            print(f"Published by: {_clean(info['publisher'])}", file=sys.stderr)
        if info.get("proved_domain"):
            # The name is the company's own words; the domain is the one it proved it controls. A copy on a look-alike site is told apart by it.
            print(f"Proved domain: {_clean(info['proved_domain'])} (the domain the company proved it controls; check it is the company you meant)", file=sys.stderr)
        print(f"Issued: {_clean(info['issued_at'])}; copy age: {_age_words(info['age_seconds'])}; good until: {_clean(info['valid_until'])}", file=sys.stderr)
    line = online_keys_line(online_keys)
    if line:
        print(line, file=sys.stderr)
    print("", file=sys.stderr)
    for r in results:
        marker = {"PASS": "passed ", "FAIL": "failed ", "DEGRADED": "notes  "}.get(r.status, "??? ")
        print(f"[{marker}] {r.check}", file=sys.stderr)
        for note in r.notes:
            print(f"        {_clean(note)}", file=sys.stderr)
        for a in r.anomalies:
            print(f"        - {_clean(a.get('kind', 'anomaly'))}: {_clean(a.get('message', ''))}", file=sys.stderr)
    if feed_signature_held(outcome):
        print("\nItems, as this copy states them:", file=sys.stderr)
        for it in info["items"]:
            ver = f" v{_clean(it['version'])}" if "version" in it else ""
            print(f"  {_clean(it['check_code'])}  {_clean(it['title'])}{ver}  [{_clean(it['access'])}; {_clean(it['record_status'])}]", file=sys.stderr)
    print(f"\nOverall: {result_word(summary['overall_status'])}", file=sys.stderr)
    _say_json_follows()
    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if summary["overall_status"] == "PASS" else 1


def run_all_checks(bundle_dir: Path, trusted_keys: Optional[list[dict[str, Any]]] = None) -> list[CheckResult]:
    """Execute the core checks (+ the supplementary file-checksum
    check) and return their results in priority order.
    """
    package_root, bundle_dir = resolve_layout(bundle_dir)
    manifest = _read_json(bundle_dir / "MANIFEST.json")
    events = _read_jsonl(bundle_dir / "events.jsonl")
    chain_root = _read_json(bundle_dir / "chain_root.json")
    pem_path = bundle_dir / "public_key.pem"
    public_key_pem = pem_path.read_bytes() if pem_path.exists() else None

    results: list[CheckResult] = []

    # Priority order matches the MR brief.
    session_path = bundle_dir / SESSION_CHECKPOINTS_FILE
    try:
        session_doc = _read_json(session_path)
    except ValueError:
        session_doc = {}  # unparseable: present, so session mode, and malformed -> FAIL
    if session_doc is None and session_path.exists():
        session_doc = {}  # JSON null: present but malformed
    session_mode = session_checkpoints_present(session_doc)
    results.append(check_hash_chain(events, session_doc, trusted_keys, chain_root, manifest))
    statement_path = bundle_dir / "withheld_positions.json"
    withheld_report = check_withheld_positions(
        events, statement_path.read_bytes() if statement_path.exists() else None,
        chain_root, trusted_keys,
    )
    if withheld_report is not None:
        results.append(withheld_report)
    results.append(check_chain_completeness(events, chain_root, session_mode))
    results.append(
        check_chain_root_signature(chain_root, public_key_pem, events, trusted_keys, session_mode)
    )
    results.append(check_verifier_verdict_presence(events))
    results.append(check_sod(events))
    results.append(check_two_act(events))
    results.append(check_member_attestation(events))
    results.append(check_skill_provenance(events))
    results.append(check_reproducibility_tuple(events))
    results.append(check_prompt_integrity(events, bundle_dir))
    # Supplementary check - not one of the seven but cheap + load-bearing.
    manifest_path = bundle_dir / "MANIFEST.json"
    seal_path = bundle_dir / PACKAGE_SEAL_FILE
    results.append(check_file_checksums(
        package_root, manifest,
        seal_path.read_bytes() if seal_path.exists() else None,
        manifest_path.read_bytes() if manifest_path.exists() else None,
        chain_root, trusted_keys, public_key_pem, bundle_dir,
    ))

    return results


# Human-readable result words. The JSON report keeps PASS / DEGRADED / FAIL
# exactly; only the text printed for a person uses these (the "Degraded" label
# read as broken to an auditor, but it means the record is intact with notes).
RESULT_WORDS = {"PASS": "Passed", "DEGRADED": "Passed with notes", "FAIL": "Failed"}


def result_word(status: str) -> str:
    return RESULT_WORDS.get(status, status)


def package_code(chain_root: dict[str, Any]) -> str:
    """The package code printed on the cover of the package: the first 12 hex
    characters of the signed chain head (chain_root.head_event_hash, base64 of
    32 raw bytes), upper-case, grouped 4-4-4. Empty when there is no head."""
    head = chain_root.get("head_event_hash") if isinstance(chain_root, dict) else None
    if not isinstance(head, str) or not head:
        return ""
    try:
        h = base64.b64decode(head, validate=True).hex()[:12].upper()
    except Exception:  # noqa: BLE001
        return ""
    if len(h) < 12:
        return ""
    return f"{h[0:4]}-{h[4:8]}-{h[8:12]}"


def summarise(results: list[CheckResult]) -> dict[str, Any]:
    """Build the structured JSON-output summary."""
    by_status: dict[str, int] = {"PASS": 0, "FAIL": 0, "DEGRADED": 0}
    for r in results:
        by_status[r.status] = by_status.get(r.status, 0) + 1
    return {
        "schema_version": "v1",
        "verifier_version": VERIFIER_VERSION,
        "overall_status": (
            "FAIL"
            if by_status.get("FAIL", 0) > 0
            else (
                "DEGRADED"
                if by_status.get("DEGRADED", 0) > 0
                else "PASS"
            )
        ),
        "summary": by_status,
        "checks": [_check_dict(r) for r in results],
    }


def _check_dict(r: CheckResult) -> dict[str, Any]:
    """A check's JSON form; the optional details block is left out when empty."""
    d = asdict(r)
    if not d.get("details"):
        d.pop("details", None)
    return d


def _headline_counts(results: list[CheckResult]) -> dict[str, Any]:
    """Derive the headline numbers shown above the trust-claim block.

    Numbers are taken from check results so the auditor sees the actual
    bundle scope, not a hardcoded sample. Strings are deliberately short
    ('yes' / 'no' / 'degraded' / 'incomplete') for scan speed.
    """
    by_check = {r.check: r for r in results}

    # Events checked = the count the hash-chain check walked.
    chain = by_check.get("hash_chain_integrity")
    events_checked = chain.count if chain else 0

    # Signature verified is binary from the chain-root-signature check.
    sig = by_check.get("chain_root_signature")
    if sig is None:
        sig_str = "no"
    elif sig.status == "PASS":
        sig_str = "yes"
    elif sig.status == "DEGRADED":
        sig_str = "degraded"
    else:
        sig_str = "no"

    # Separation of duties is reported as a split, never as "complete": a
    # tenant may let the author seal routine record kinds under its own policy,
    # so the honest number is how many were author-sealed and how many had a
    # second person.
    sod = by_check.get("sod_separation_of_duties")
    if sod is None:
        sod_headline = "not checked"
    elif sod.status == "FAIL":
        sod_headline = "separation of duties NOT upheld"
    else:
        d = sod.details or {}
        parts = [f"{d.get('author_sealed_under_policy', 0)} author-sealed under policy"]
        exceptions = d.get("sole_admin_exceptions", 0)
        if exceptions:
            parts.append(
                f"{exceptions} sole-admin exception{'' if exceptions == 1 else 's'}"
            )
        parts.append(f"{d.get('dual_controlled', 0)} dual-controlled")
        sod_headline = "; ".join(parts)
        if sod.status == "DEGRADED":
            sod_headline += " (some evidence could not be verified)"

    # Replay details = count of verifier verdicts with the tier-3
    # reproducibility tuple. We use the tuple-completeness check count
    # minus any "incomplete" anomalies.
    repro = by_check.get("reproducibility_tuple_completeness")
    if repro is None:
        replay_count = 0
    else:
        incomplete = sum(
            1 for a in repro.anomalies
            if a.get("kind") in (
                "reproducibility_tuple_incomplete",
                "llm_tier_tuple_incomplete",
            )
        )
        replay_count = max(repro.count - incomplete, 0)

    return {
        "events": events_checked,
        "signature_verified": sig_str,
        "sod_headline": sod_headline,
        "replay_details_count": replay_count,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="verify.py",
        description=(
            "Offline verifier for Kanonik Auditor Export bundles. "
            "Validates hash chain, chain-root signature, Verifier "
            "verdict presence, separation of duties, skill provenance, "
            "and reproducibility tuples. Air-gapped by default."
        ),
    )
    parser.add_argument(
        "bundle",
        nargs="?",
        default=None,
        help="Path to extracted bundle directory OR a .tar.gz bundle (or, with --record or --disclosure, one .json file)",
    )
    parser.add_argument(
        "--feed",
        default=None,
        metavar="FEED.JSON",
        help=(
            "Verify a signed trust feed (a kanonik-trust-feed/v1 .json a company re-hosts): schema, signature against the "
            "pinned keys, how old the copy is (STALE past valid_until), and each item's code and status words. With "
            "--online, also fetch the live feed from share.kanonik.ai and list the differences by item. With "
            "--disclosure ITEM.json, also confirm the item's signed manifest digest is listed in the feed."
        ),
    )
    parser.add_argument(
        "--record",
        action="store_true",
        help=(
            "Verify a single-record proof file (proof-<kind>-<id>.json) a company "
            "handed you instead of a whole bundle: event hash, signed checkpoint, "
            "verdict, approval, currency."
        ),
    )
    parser.add_argument(
        "--disclosure",
        action="store_true",
        help=(
            "Verify a signed disclosure file (a kanonik-disclosure/v1 .json a company shared with you): "
            "schema, signature against the pinned keys, and (with --online) whether it is still current "
            "and still shared."
        ),
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help=(
            "Also fetch Kanonik's published chain-root public keys from the "
            "well-known URL and add them to the pinned set (for a key rotated "
            "after this verifier shipped). With --feed, also fetch the live feed "
            "from share.kanonik.ai. Offline verification against the "
            "built-in pinned keys is the default and needs no network."
        ),
    )
    parser.add_argument(
        "--trusted-keys",
        default=None,
        metavar="PATH",
        help=(
            "Path to an ADDITIONAL chain-root trusted-keys JSON file (same shape "
            "as the shipped trusted_keys.json) whose keys are added to the "
            "built-in pinned set. For pinning a key the shipped verifier does "
            "not yet carry."
        ),
    )
    args = parser.parse_args(argv)

    if args.feed is None and args.bundle is None:
        parser.error("the following arguments are required: bundle")
    if args.feed is not None and args.record:
        print("error: use --feed or --record, not both", file=sys.stderr)
        return 2
    if args.feed is not None and args.bundle is not None and not args.disclosure:
        print("error: with --feed, a second file is only read together with --disclosure", file=sys.stderr)
        return 2

    trusted_keys, online_keys = load_trusted_keys_report(
        Path(args.trusted_keys).expanduser() if args.trusted_keys else None,
        online=args.online,
    )

    if args.feed is not None:
        feed_path = Path(args.feed).expanduser()
        if not feed_path.exists():
            print(f"error: feed file not found: {feed_path}", file=sys.stderr)
            return 2
        item_path = Path(args.bundle).expanduser() if args.bundle is not None else None
        if args.disclosure and item_path is None:
            print("error: --feed with --disclosure needs the item file: verify.py --feed feed.json --disclosure item.json", file=sys.stderr)
            return 2
        if item_path is not None and not item_path.exists():
            print(f"error: disclosure file not found: {item_path}", file=sys.stderr)
            return 2
        return run_feed_mode(feed_path, trusted_keys, args.online, online_keys, item_path)

    bundle_path = Path(args.bundle).expanduser()
    if not bundle_path.exists():
        print(
            f"error: bundle path not found: {bundle_path}",
            file=sys.stderr,
        )
        return 2

    if args.record and args.disclosure:
        print("error: use --record or --disclosure, not both", file=sys.stderr)
        return 2
    if args.record:
        return run_record_mode(bundle_path, trusted_keys, online_keys)
    if args.disclosure:
        return run_disclosure_mode(bundle_path, trusted_keys, args.online, online_keys)

    try:
        bundle_dir = load_bundle(bundle_path)
    except (ValueError, FileNotFoundError, tarfile.TarError) as e:
        print(f"error: could not load bundle: {e}", file=sys.stderr)
        return 2

    try:
        results = run_all_checks(bundle_dir, trusted_keys)
    except Exception as e:  # noqa: BLE001
        print(f"error: verifier crashed: {e}", file=sys.stderr)
        return 2

    summary = summarise(results)
    summary["online_keys"] = online_keys

    # Trust-claim headline - the FIRST line an auditor sees.
    # Per docs/journeys/persona-journey-strategy.md §"Auditor Export Copy":
    # the auditor can check the bundle without asking Kanonik, and the line
    # names what is still relied on.
    # Lead with that, then the verification result, on PASS, FAIL and
    # DEGRADED alike.
    print(
        "You can check this bundle without asking Kanonik. What you still rely on Kanonik for: the pinned signing keys, the withheld-entries list and the prompt registry in this checker.",
        file=sys.stderr,
    )
    print("", file=sys.stderr)

    # Verification result block - human-grade summary of the structured
    # checks. Numbers are dynamic so the auditor sees the actual scope.
    headline_status = result_word(summary["overall_status"])
    counts = _headline_counts(results)
    print(f"Bundle verification: {headline_status}", file=sys.stderr)
    print(f"Checker version: {VERIFIER_VERSION}", file=sys.stderr)
    if online_keys_line(online_keys):
        print(online_keys_line(online_keys), file=sys.stderr)
    sig_res = next((r for r in results if r.check == "chain_root_signature"), None)
    code = package_code(_read_json(resolve_layout(bundle_dir)[1] / "chain_root.json"))
    if code and (sig_res is None or sig_res.status != "FAIL"):
        print(f"Package code: {code}", file=sys.stderr)
    elif code:
        print("Package code: not shown (the seal did not verify)", file=sys.stderr)
    print(f"Events checked: {counts['events']}", file=sys.stderr)
    print(
        f"Signature verified: {_signature_words(counts['signature_verified'])}",
        file=sys.stderr,
    )
    print(
        f"Separation of duties: {counts['sod_headline']}",
        file=sys.stderr,
    )
    print(
        "Replay details present: "
        f"{counts['replay_details_count']} AI decisions",
        file=sys.stderr,
    )
    print("", file=sys.stderr)

    # Per-check detail (unchanged shape; the load-bearing detail an
    # auditor drills into after they have the headline).
    print("Kanonik Auditor Export - offline verification", file=sys.stderr)
    print("=" * 50, file=sys.stderr)
    for r in results:
        marker = {"PASS": "passed ", "FAIL": "failed ", "DEGRADED": "notes  "}.get(
            r.status, "??? "
        )
        print(
            f"[{marker}] {r.check}  ({r.count} item{'s' if r.count != 1 else ''})",
            file=sys.stderr,
        )
        for note in r.notes:
            print(f"        {note}", file=sys.stderr)
        for a in r.anomalies:
            kind = a.get("kind", "anomaly")
            msg = a.get("message", "")
            print(f"        - {kind}: {msg}", file=sys.stderr)
    print(
        f"\nOverall: {result_word(summary['overall_status'])}  "
        f"({summary['summary'].get('PASS', 0)} passed, "
        f"{summary['summary'].get('DEGRADED', 0)} with notes, "
        f"{summary['summary'].get('FAIL', 0)} failed)",
        file=sys.stderr,
    )

    # Machine-readable JSON on stdout. It spells the result PASS, DEGRADED, FAIL (programs read it); say once, in words,
    # that DEGRADED is the "Passed with notes" above, so a person who reads the JSON does not see a second verdict.
    _say_json_follows()
    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")

    return 0 if summary["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
