// editorconfig-checker-disable-file
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Kanonik / eugene_gl
//
// verify.mjs - the browser/Node verifier core for Kanonik Auditor Export
// bundles. A dependency-free, web-standard-only port of chain/verify.py: it
// runs the SAME eight offline checks, entirely in the browser (or Node 18+),
// with NO install and NO Python. It is inlined into chain/verify.html (the
// zero-install, drag-and-drop front door) and is drift-checked byte-for-byte
// against verify.py by the auditorexport parity test.
//
// Web-standard APIs only: crypto.subtle (SHA-256 + ECDSA P-384/SHA-384),
// DecompressionStream("gzip"), TextEncoder, atob/Uint8Array. All present in
// modern browsers and in Node >= 18 (globalThis.crypto). No network calls.
//
// The port mirrors chain/canonical_json.py + chain/event_hash.py exactly for
// the two hashing paths (per-event chain hash + chain-root signed payload).
// Because the per-event payload is hashed as OPAQUE base64 bytes (never
// re-canonicalised), the only canonical-JSON path is the fixed-shape
// chain-root payload (ints + strings, no floats) - so there is no float
// round-trip risk.

// ── low-level encoders (mirror event_hash.py) ───────────────────────────────

const HASH_SIZE = 32;
const NULL_LEN = 0xffffffff;
const ZERO_UUID = "00000000-0000-0000-0000-000000000000";
const te = new TextEncoder();

// How many ids a summary note names before it stops listing and says how many
// more there are. A report that prints one line per record stops being a
// report; the complete list is always available from verify.py.
const SAMPLE_LIMIT = 8;

// VERIFIER_VERSION is this offline verifier's own version, distinct from the
// bundle schema_version. Version 2.0.0 recognises the record-kind self-seal:
// one person accepting AND sealing a routine record (evidence, a control test,
// a mapping) that the tenant's author-may-self-seal policy permits without a
// second reviewer, disclosed with no separate exception event. An export that
// contains such a self-seal requires verifier version 2.0.0 or later; an older
// 1.x copy reports those approvals as self_approval failures because it predates
// the rule.
//
// Version 2.1.0 adds the two-act oversight check: a governance record the author
// only ACCEPTED (parked for a second person) must be sealed later by a DIFFERENT
// subject before it commits. A record kind the author sealed with one click
// needs no second person and is never asked to show one. This check is additive
// and never changes the verdict of any check that shipped in 2.0.0. Every export
// produced before the record-kind self-seal, and every governance-kind or
// sole-admin case, still verifies unchanged on the verifier it originally
// shipped with.
//
// Version 2.2.0 adds the per-member attestation check: an approval produced under
// the recorded-click regime carries attestation_required=true (in the hashed
// payload), and every member must then carry a non-empty attestation. Additive
// and gated on the approval's own flag, so exports that predate the regime still
// verify unchanged. Kept byte-identical to the verify.py VERIFIER_VERSION.
//
// Version 2.4.0 adds the single-record mode (verifyRecordProof): one sealed record
// with its signed record checkpoint, verified without the rest of the chain. The
// bundle path is unchanged. Kept byte-identical to the verify.py VERIFIER_VERSION.
// Version 2.5.0 adds obligation, lens_decision and lens_applicability to the
// author-may-self-seal default and the rule-tier-only set. Version 2.6.0 adds
// migration_summary to both (the bounded population of a legacy export). Kept byte-identical
// to the verify.py VERIFIER_VERSION.
// Version 2.7.0 adds risk and remediation to the author-may-self-seal default
// (a risk entry and a corrective action); the rule-tier-only set is unchanged.
// Version 2.7.1 lets a NOT_ASSESSED verdict with a recorded human approver
// stand, like HUMAN_REVIEW. 2.8.0 is reserved for the checks of the next
// pack format (v2), so a v2 pack stamped min 2.8.0 is refused here.
// Version 2.7.3 verifies a skill activation's signature against the pinned
// first-party skill-signing key; an activation with no signature is DEGRADED.
// Version 2.7.4 classifies every gated write, not only *.committed.v1: six
// human-decision writes are verdict-exempt and counted, the audit session joins
// the historical-optional kinds (an absent verdict DEGRADES), and an unknown event carrying an approval token and an
// approver FAILs (gated_write_unclassified).
// Version 2.7.4 also requires a separate approval.override.recorded.v1 for a
// REJECTED verdict and recomputes the sole-admin count from role events.
// Version 2.7.4 also lets a bundle WITHHOLD events outside the reader's grant (the
// commercial relationship with Kanonik): the hash-chain check accepts the stored
// event_hash of a well-formed withheld entry, still checks every link around it,
// and refuses a withheld marker on an entry that carries content or identity. The
// positions are reported in their own check: DEGRADED unless a signed
// withheld_positions.json (2.7.8) accounts for each one, then PASS (verify.py).
// 2.7.14 (2026-10-21): the seal covers the files; see verify.py. Kept byte-identical to the verify.py VERIFIER_VERSION.
// 2.7.15 (2026-10-21): a package that was sealed cannot be unsealed; see verify.py. Kept byte-identical to the verify.py VERIFIER_VERSION.
// 2.7.16 (2026-10-22): a withdrawn link is classified (link.retracted.v1, exempt); see verify.py.
// 2.7.17 (2026-10-22): the trust page kinds (sod catalogue version 2); see verify.py. Kept byte-identical to the verify.py VERIFIER_VERSION.
// 2.7.18 (2026-10-22): a person's acknowledgement of the company's own policy is classified; see verify.py.
// 2.7.19 (2026-10-24): `--disclosure` reads a signed kanonik-disclosure/v1 file, and the key file is version 2 (status,
// continuity); see verify.py. Kept byte-identical to the verify.py VERIFIER_VERSION.
// 2.7.20 (2026-11-02): `--feed` reads a signed kanonik-trust-feed/v1 file: STALE, the copy's age, `--online`
// differences, a feed checked against a disclosure; see verify.py. Kept byte-identical to the verify.py VERIFIER_VERSION.
// 2.7.21 (2026-11-10): words only; see verify.py (which checks' text changed). Kept byte-identical to the verify.py VERIFIER_VERSION.
// 2.7.22 (2026-11-12): graded-content pairing of a refined record's verdict; see verify.py.
const VERIFIER_VERSION = "2.7.22";
const SAMPLE_KEY_NOTE = "signed with the Kanonik public sample key: synthetic data, not a customer record";
// Amendment 9: new sampling files use the existing generic checksum check.
// Packaging release number is not admission of Amendment 7 pack checks.
const MAX_SUPPORTED_BUNDLE_REQUIREMENT = "2.7.4";

function concatBytes(chunks) {
  let n = 0;
  for (const c of chunks) n += c.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}

// Parse "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" to its 16 raw bytes.
function uuidBytes(s) {
  const hex = String(s).replace(/-/g, "");
  if (hex.length !== 32 || /[^0-9a-fA-F]/.test(hex)) {
    throw new Error(`invalid uuid: ${s}`);
  }
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function b64ToBytes(b64) {
  if (!b64) return new Uint8Array(0);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

const buf = () => {
  const chunks = [];
  return {
    utf8(s) {
      const raw = te.encode(s);
      chunks.push(u32be(raw.length), raw);
    },
    optUtf8(s) {
      if (!s) {
        chunks.push(u32be(NULL_LEN));
        return;
      }
      this.utf8(s);
    },
    uuid(s) {
      chunks.push(uuidBytes(s));
    },
    optUuid(s) {
      if (!s || s === ZERO_UUID) {
        chunks.push(u32be(NULL_LEN));
        return;
      }
      chunks.push(u32be(16), uuidBytes(s));
    },
    raw(bytes) {
      chunks.push(bytes);
    },
    lenBytes(bytes) {
      chunks.push(u32be(bytes.length), bytes);
    },
    done() {
      return concatBytes(chunks);
    },
  };
};

// Mirror event_hash.py format_rfc3339_nano_utc for UTC timestamps: keep the
// second-precision head, strip trailing zeros from the fractional seconds,
// append 'Z'. Parsed by string (NOT Date) so microsecond digits survive.
function rfc3339NanoUTC(value) {
  if (typeof value !== "string") throw new Error("a signed time is not a string");
  let v = value.trim();
  // Normalise a +00:00 offset to Z; all chain timestamps are UTC.
  if (v.endsWith("+00:00")) v = v.slice(0, -6) + "Z";
  const m = v.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$/);
  if (!m) throw new Error(`unsupported timestamp: ${value}`);
  let out = m[1];
  if (m[2]) {
    const frac = m[2].replace(/0+$/, "");
    if (frac) out += "." + frac;
  }
  return out + "Z";
}

async function sha256(bytes) {
  const d = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(d);
}

// Recompute the SHA-256 chain hash for one event row (mirror
// event_hash.py compute_event_hash).
async function computeEventHash(ev) {
  const b = buf();
  b.uuid(ev.tenant_id);
  b.uuid(ev.event_id);
  b.utf8(ev.event_type);
  b.utf8(ev.schema_version);
  b.optUtf8(ev.entity_type || "");
  b.optUuid(ev.entity_id);
  b.uuid(ev.idempotency_key);
  b.utf8(rfc3339NanoUTC(ev.transaction_time));
  b.utf8(rfc3339NanoUTC(ev.valid_time));
  b.utf8(ev.caller_subject);
  b.optUuid(ev.caller_session);
  b.optUtf8(ev.caller_tool || "");
  const prev = ev.prev_hash ? b64ToBytes(ev.prev_hash) : new Uint8Array(HASH_SIZE);
  if (prev.length !== HASH_SIZE) throw new Error("prev_hash must be 32 bytes");
  b.raw(prev);
  b.lenBytes(ev.payload ? b64ToBytes(ev.payload) : new Uint8Array(0));
  return sha256(b.done());
}

// ── canonical JSON (mirror canonical_json.py) - used only for the fixed-shape
// chain-root payload, so only strings + integers occur. ────────────────────

const ESCAPES = {
  0x22: '\\"',
  0x5c: "\\\\",
  0x08: "\\b",
  0x0c: "\\f",
  0x0a: "\\n",
  0x0d: "\\r",
  0x09: "\\t",
};

function encStr(s) {
  let out = '"';
  for (const ch of te.encode(s)) {
    if (ESCAPES[ch] !== undefined) out += ESCAPES[ch];
    else if (ch < 0x20) out += "\\u" + ch.toString(16).padStart(4, "0");
    else out += String.fromCharCode(ch);
  }
  return out + '"';
}

function cmpCodePoints(a, b) {
  const x = Array.from(a, (c) => c.codePointAt(0));
  const y = Array.from(b, (c) => c.codePointAt(0));
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

function canonicalMarshal(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "string") return encStr(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("canonical: non-finite number");
    if (Number.isInteger(v)) return String(v);
    // No floats occur in the chain-root payload; guard defensively.
    return String(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonicalMarshal).join(",") + "]";
  if (typeof v === "object") {
    // Go sorts keys by UTF-8 bytes and Python by code point: the same order. JavaScript's default sort is by UTF-16
    // code unit, which differs for characters above U+FFFF, so compare code points.
    const keys = Object.keys(v).sort(cmpCodePoints);
    return "{" + keys.map((k) => encStr(k) + ":" + canonicalMarshal(v[k])).join(",") + "}";
  }
  throw new Error("canonical: unsupported type");
}

// A sequence number beyond 2^53-1 would be rounded by parseInt: two different numbers would sign alike. Refused, so
// the payload is never rebuilt from a rounded value. verify.py reads the exact integer and its signature fails.
// A signed text field is a string, or absent. Anything else (an array that prints like a string, a number) is not
// what the signer signed.
function sameSeq(a, b) {
  try {
    return safeSeq(a) === safeSeq(b);
  } catch {
    return false;
  }
}

function strOrNull(v) {
  if (v === undefined || v === null || v === "") return null;
  if (typeof v !== "string") throw new Error("a signed text field is not a string");
  return v;
}

function safeSeq(v) {
  // Validated BEFORE conversion: parseInt("1e21") is 1 and parseInt("1.9junk") is 1, which would sign alike.
  const n = typeof v === "number" ? v : typeof v === "string" && /^[0-9]+$/.test(v) ? Number(v) : NaN;
  if (!Number.isSafeInteger(n)) throw new Error("sequence number is not a safe integer");
  return n;
}

function chainRootSignedPayload(root) {
  const headHash = root.head_event_hash;
  if (typeof headHash !== "string") throw new Error("chain_root: head_event_hash missing");
  const signedAt = root.signed_at;
  if (!signedAt) throw new Error("chain_root: signed_at missing");
  const chainLength = "chain_length" in root ? root.chain_length : root.ChainLength;
  const version = root.version || "v1";
  const payload = {
    version,
    tenant_id: strOrNull(root.tenant_id),
    highest_seq: safeSeq(chainLength),
    highest_hash: headHash,
    signed_at: rfc3339NanoUTC(signedAt),
    signer_key_id: strOrNull(root.signing_key_id),
  };
  return canonicalBytes(payload);
}

// ── ECDSA P-384 signature verify (WebCrypto) ─────────────────────────────────

// WebCrypto ECDSA verify wants the raw r||s (2*48 bytes for P-384); Go signs
// ASN.1/DER (SEQUENCE{INTEGER r, INTEGER s}). Convert DER -> raw.
function derToRawEcdsa(der, size) {
  // The whole signature must be one DER SEQUENCE of two INTEGERs and nothing else: the Python checker's library
  // rejects trailing bytes and a wrong declared length, so this does too, or one signature would read two ways.
  let i = 0;
  if (der[i++] !== 0x30) throw new Error("sig: expected SEQUENCE");
  let seqLen = der[i++];
  if (seqLen === undefined) throw new Error("sig: truncated");
  if (seqLen & 0x80) {
    const n = seqLen & 0x7f;
    if (n === 0 || n > 4) throw new Error("sig: bad length");
    seqLen = 0;
    for (let k = 0; k < n; k++) seqLen = seqLen * 256 + (der[i++] ?? 0);
    if (seqLen < 128) throw new Error("sig: length not minimal");
  }
  if (i + seqLen !== der.length) throw new Error("sig: length does not match the bytes");
  const readInt = () => {
    if (der[i++] !== 0x02) throw new Error("sig: expected INTEGER");
    let len = der[i++];
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 4) throw new Error("sig: bad length");
      len = 0;
      for (let k = 0; k < n; k++) len = len * 256 + (der[i++] ?? 0);
      if (len < 128) throw new Error("sig: length not minimal");
    }
    if (len === 0 || i + len > der.length) throw new Error("sig: truncated");
    let val = der.slice(i, i + len);
    i += len;
    // DER integers are positive and minimal: no sign bit set, no redundant leading zero.
    if ((val[0] & 0x80) !== 0 || (val.length > 1 && val[0] === 0x00 && (val[1] & 0x80) === 0)) throw new Error("sig: integer not canonical");
    // strip leading zero padding, then left-pad to `size`.
    while (val.length > 0 && val[0] === 0x00) val = val.slice(1);
    if (val.length > size) throw new Error("sig: integer too large");
    const out = new Uint8Array(size);
    out.set(val, size - val.length);
    return out;
  };
  const r = readInt();
  const s = readInt();
  if (i !== der.length) throw new Error("sig: trailing bytes");
  return concatBytes([r, s]);
}

function pemToDer(pem) {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  return b64ToBytes(b64);
}

// DEFAULT_TRUSTED_KEYS: the canonical pinned chain-root keys,
// mirrored from trusted_keys.json (the auditorexport parity test guards drift).
// The signature is verified against THESE, never the key the bundle ships.
// env=production -> PASS; env=dev -> DEGRADED (not production-attested).
const DEFAULT_TRUSTED_KEYS = [
  {
    "signing_key_id": "chain-root:v1@vault",
    "env": "production",
    "status": "active",
    "sha256_spki_der": "4037e409f864b8149b9f5d021122e1fd2bea3bbec1504a1e2716ba1411c5df1d",
    "seal_required_from": "2026-11-01T00:00:00Z",
    "pem": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEaoCdQeFBb/tAPcfs54JU/VxMzbA05ua5\noSBkuvKnl5wS5GPqIpekksoA/ZmU28E7tAmwjKpI+zpDtIN+ET+rjIM27JnRD8fr\n6d13DzGlJED1n7z0nyXWhOsYaQetPxwf\n-----END PUBLIC KEY-----\n"
  },
  {
    "signing_key_id": "chain-root:v1@vault",
    "env": "dev",
    "status": "active",
    "label": "integration",
    "sha256_spki_der": "7b7dba090c3c7168d7880b95144b25e436ce01e63350e69aa164857390acbc84",
    "seal_required_from": "2026-10-22T00:00:00Z",
    "pem": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEW+lI5s8xYdwpEVZNEGa091bltFFIRImb\n65Dz/f3gSP1IUz8uagVDaaDYJZ70d/XQ82DM9VOrfGLpAoKj0/gXPX8aDHJeGqsE\nDUW3c5lvcMuIik8klFQvpo2YHyh1oK7W\n-----END PUBLIC KEY-----\n"
  },
  {
    "signing_key_id": "kanonik-public-sample-2026-10-04",
    "class": "sample",
    "env": "sample",
    "status": "active",
    "label": "Kanonik public sample key - synthetic data only",
    "sha256_spki_der": "bd2689adf99a28d57e1a0174a3bc835b772ef02b437a5a59f9fd3bbd19fe277f",
    "seal_required_from": "2026-01-01T00:00:00Z",
    "pem": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuCibNIPNWVpJhXkG/obwIJbfood2ITdU\nuaKKdminUNxMkYqxY1bt3/3qVV7cyOXZsViP9Z5ZTUsRFm+mDVMVGIi9PlqtUPJx\n4uVrJzXw8vALKJMS1Moq7CXNQ74ZeOhs\n-----END PUBLIC KEY-----\n"
  }
];

// Chain-root payload versions (Amendment 17). "v3" has the fields and the tenant-event-count meaning of
// "v2" plus the signed claim that the package carrying the root is sealed. Mirrors verify.py.
const CHAIN_ROOT_V3 = "v3";
const CHAIN_ROOT_VERSIONS = ["v1", "v2", CHAIN_ROOT_V3];
const TENANT_PURE_ROOT_VERSIONS = ["v2", CHAIN_ROOT_V3];

// Canonical base64 only (the alphabet, padding to a multiple of four, nothing else): the one way verify.py reads a
// chain-root signature, so a hand-edited string is read the same by both checkers.
function strictRootB64(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4) throw new Error("invalid base64");
  const raw = b64ToBytes(s);
  if (bytesToB64(raw) !== s) throw new Error("base64 is not canonical"); // non-zero padding bits decode alike
  return raw;
}

// verifySigAgainstTrusted returns the trusted-key entry whose public key
// verifies the raw ECDSA sig over signedBytes, or null. The bundle's own key
// is never consulted here.
async function verifySigAgainstTrusted(sigRaw, signedBytes, trustedKeys) {
  for (const k of await consolidateKeys(trustedKeys)) {
    if (k.status === "revoked") continue; // a revoked key vouches for nothing it ever signed
    const pem = typeof k.pem === "string" ? k.pem : new TextDecoder().decode(k.pem);
    try {
      const key = await globalThis.crypto.subtle.importKey("spki", pemToDer(pem), { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
      const ok = await globalThis.crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, sigRaw, signedBytes);
      if (ok) return k;
    } catch { /* try the next pinned key */ }
  }
  return null;
}


async function verifyChainRootSignature(root, publicKeyPem, events, trustedKeys, sessionMode = false) {
  const notes = [];
  const anomalies = [];
  const R = (status) => ({ check: "chain_root_signature", status, count: 0, notes, anomalies });
  if (!root) return { check: "chain_root_signature", status: "FAIL", count: 0, notes: [], anomalies: [{ kind: "chain_root_missing", message: "chain_root.json not in bundle" }] };
  const rootVersion = String(root.version || root.Version || "v1");
  if (!CHAIN_ROOT_VERSIONS.includes(rootVersion)) {
    return { check: "chain_root_signature", status: "FAIL", count: 0, notes: [], anomalies: [{ kind: "chain_root_version_unknown", message: `this package's chain root has version '${rootVersion}', which this checker does not know. Use a current checker; do not read the package as an older one.` }] };
  }
  const sigB64 = root.signature || "";
  if (!sigB64) {
    return { check: "chain_root_signature", status: "FAIL", count: 0, notes: [], anomalies: [{ kind: "chain_root_unsigned", message: "chain_root.json has no signature, so Kanonik did not attest to this package's chain. A package Kanonik exports is always signed; if this one was, the signature was removed. Do not rely on this package." }] };
  }
  let sigRaw, signedBytes, sigDer;
  try {
    sigDer = strictRootB64(sigB64);
  } catch (e) {
    anomalies.push({ kind: "signature_b64_invalid", message: `chain_root.signature is not valid base64: ${e}` });
    return R("FAIL");
  }
  // Bytes that are not one canonical DER signature verify against no key, as in verify.py.
  try { sigRaw = derToRawEcdsa(sigDer, 48); } catch { sigRaw = new Uint8Array(96); }
  try {
    signedBytes = chainRootSignedPayload(root);
  } catch (e) {
    anomalies.push({ kind: "signature_verification_error", message: String(e) });
    return R("FAIL");
  }
  trustedKeys = trustedKeys || [];
  let matched = null;
  let status = "PASS";
  if (trustedKeys.length) {
    // Verify against the PINNED trust anchor, never the bundle's key.
    matched = await verifySigAgainstTrusted(sigRaw, signedBytes, trustedKeys);
    if (!matched) {
      anomalies.push({ kind: "chain_root_key_untrusted", signing_key_id: root.signing_key_id || "", message: "the chain-root signature does not verify against any PINNED Kanonik key (trusted_keys / --trusted-keys / --online): re-signed with a foreign key, tampered, or a key not yet pinned. The bundle's own signing_public_key_pem is intentionally NOT trusted." });
      return R("FAIL");
    }
  } else {
    // No pinned trust anchor: fall back to the bundle's own key, but DEGRADE.
    let pem = publicKeyPem;
    if (!pem || !pem.trim()) {
      const inline = root.signing_public_key_pem || "";
      if (inline) pem = new TextDecoder().decode(b64ToBytes(inline));
      else { anomalies.push({ kind: "public_key_missing", message: "no pinned trust anchor and no key in the bundle; cannot verify the signature offline" }); return R("FAIL"); }
    }
    try {
      const key = await globalThis.crypto.subtle.importKey("spki", pemToDer(pem), { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
      const ok = await globalThis.crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, sigRaw, signedBytes);
      if (!ok) { anomalies.push({ kind: "signature_verification_failed", message: "ECDSA P-384 + SHA-384 signature does NOT verify against the bundled public key" }); return R("FAIL"); }
    } catch (e) {
      anomalies.push({ kind: "signature_verification_error", message: String(e) });
      return R("FAIL");
    }
    status = "DEGRADED";
    notes.push("no pinned Kanonik trust anchor was available, so the signature was verified only against the key the BUNDLE carries; that is not an independent check.");
  }
  if (events && events.length && !sessionMode) {
    const last = events.reduce((a, b) => (seq(a) >= seq(b) ? a : b));
    if ((root.head_event_hash || "") !== (last.event_hash || "")) {
      anomalies.push({ kind: "chain_root_head_mismatch", message: "chain_root.head_event_hash does not match the highest-sequence event_hash" });
      return R("FAIL");
    }
  }
  if (matched) {
    if (matched.class === "sample") {
      status = "DEGRADED";
      notes.push(SAMPLE_KEY_NOTE);
    } else if ((matched.env || "") === "production") {
      notes.push(`ECDSA P-384 + SHA-384 signature verified against Kanonik's PINNED PRODUCTION signing key (id ${JSON.stringify(matched.signing_key_id || "")}); chain root attestable to Kanonik as of ${root.signed_at}`);
    } else {
      status = "DEGRADED";
      const label = matched.label || matched.env || "non-production";
      notes.push(`signature verified against a pinned NON-PRODUCTION Kanonik key (env=${matched.env || "dev"}, ${label}); the chain root is structurally sound but is NOT attestable to Kanonik's PRODUCTION signing key. Expected for integration/dev bundles.`);
    }
  }
  return R(status);
}

// ── single-record proof (mirror verify.py run_record_checks) ─────────────────

const RECORD_PROOF_SCHEMA = "record_proof.v1";
const RECORD_RULE_TIER_ONLY_KINDS = new Set(["questionnaire_response", "obligation", "lens_decision", "lens_applicability", "migration_summary", "policy_acknowledgement"]);
const RECORD_VERDICT_REQUIRED = ["model", "model_provider", "prompt_version", "prompt_content_hash"];
const RECORD_KNOWN_DECISION_BASES = new Set(["sealed_by_other", "author_self_seal_sole_sealer", "author_self_seal_record_kind"]);
const RECORD_CATALOGUE_SELF_SEAL = new Set(["evidence", "control_test", "audit_finding", "audit_session", "asset", "vendor", "mapping", "link", "claim", "questionnaire_response", "obligation", "lens_decision", "lens_applicability", "migration_summary", "disclosure", "access_grant", "branding", "nda_text", "third_party_document", "policy_acknowledgement"]);

function recordCheckpointSignedPayload(cp) {
  if (typeof cp.event_hash !== "string" || !cp.event_hash) throw new Error("checkpoint: event_hash missing");
  if (!cp.signed_at) throw new Error("checkpoint: signed_at missing");
  if (!("sequence_number" in cp)) throw new Error("checkpoint: sequence_number missing");
  const payload = {
    version: cp.version || "record-v1",
    tenant_id: strOrNull(cp.tenant_id),
    highest_seq: safeSeq(cp.sequence_number),
    highest_hash: cp.event_hash,
    signed_at: rfc3339NanoUTC(cp.signed_at),
    signer_key_id: strOrNull(cp.signing_key_id),
  };
  return canonicalBytes(payload);
}

function versionTuple(v) {
  return String(v || "").split(".").map((p) => parseInt(p.replace(/\D/g, ""), 10) || 0);
}
function versionGreater(a, b) {
  const x = versionTuple(a), y = versionTuple(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] || 0) - (y[i] || 0);
    if (d !== 0) return d > 0;
  }
  return false;
}
const rec = (check, status, notes = [], anomalies = [], count = 1) => ({ check, status, count, notes, anomalies });

function checkRecordSchema(proof) {
  const anomalies = [];
  const notes = [];
  if (proof.schema_version !== RECORD_PROOF_SCHEMA) anomalies.push({ kind: "record_schema_unknown", message: `schema_version is ${JSON.stringify(proof.schema_version)}; this verifier reads ${RECORD_PROOF_SCHEMA}` });
  const min = proof.min_verifier_version;
  if (!min) anomalies.push({ kind: "record_min_version_missing", message: "the file names no minimum verifier version" });
  else if (versionGreater(min, VERIFIER_VERSION)) anomalies.push({ kind: "record_verifier_too_old", message: `the file needs verifier ${min} or later; this is ${VERIFIER_VERSION}. Ask the sender for the current toolkit.` });
  else notes.push(`file needs verifier ${min}; this is ${VERIFIER_VERSION}`);
  return rec("record_schema_and_version", anomalies.length ? "FAIL" : "PASS", notes, anomalies);
}

async function checkRecordEventHash(proof) {
  const ev = proof.event;
  if (!ev || typeof ev !== "object") return rec("record_event_hash", "FAIL", [], [{ kind: "record_event_missing", message: "the file carries no event" }], 0);
  let computed;
  try {
    computed = await computeEventHash(ev);
  } catch (e) {
    return rec("record_event_hash", "FAIL", [], [{ kind: "record_event_unhashable", message: `the event cannot be hashed: ${e.message || e}` }]);
  }
  if (bytesToB64(computed) !== (ev.event_hash || "")) return rec("record_event_hash", "FAIL", [], [{ kind: "record_event_hash_mismatch", message: "the event's content does not hash to the event_hash it states: a byte changed after the seal" }]);
  const anomalies = [];
  if (proof.kind && ev.entity_type !== proof.kind) anomalies.push({ kind: "record_kind_mismatch", message: `the file says kind ${JSON.stringify(proof.kind)} but the event is a ${JSON.stringify(ev.entity_type)}` });
  if (!String(ev.event_type || "").endsWith(".committed.v1")) anomalies.push({ kind: "record_not_a_seal", message: `the event is ${JSON.stringify(ev.event_type)}, not a sealed (committed) record` });
  const payload = decodePayload(ev);
  const statedId = payload.canonical_id || ev.entity_id || "";
  if (proof.canonical_id && statedId && proof.canonical_id !== statedId) anomalies.push({ kind: "record_id_mismatch", message: "the file's canonical_id is not the record the event carries" });
  return rec("record_event_hash", anomalies.length ? "FAIL" : "PASS", anomalies.length ? [] : ["event hash recomputed from the record's own bytes and matches"], anomalies);
}

async function checkRecordCheckpointSignature(proof, trustedKeys) {
  const cp = proof.checkpoint;
  const ev = proof.event && typeof proof.event === "object" ? proof.event : {};
  const fail = (kind, message) => rec("record_checkpoint_signature", "FAIL", [], [{ kind, message }]);
  if (!cp || typeof cp !== "object") return rec("record_checkpoint_signature", "FAIL", [], [{ kind: "record_checkpoint_missing", message: "the file carries no signed checkpoint" }], 0);
  if ((cp.version || "") !== "record-v1") return fail("record_checkpoint_version_unknown", `checkpoint version ${JSON.stringify(cp.version)}; this verifier reads record-v1`);
  if ((cp.event_hash || "") !== (ev.event_hash || "")) return fail("record_checkpoint_hash_mismatch", "the checkpoint signs a different event hash than the event in the file");
  if (!sameSeq(cp.sequence_number, ev.sequence_number)) return fail("record_checkpoint_sequence_mismatch", "the checkpoint names a different sequence number than the event");
  if ((cp.tenant_id || "") !== (ev.tenant_id || "")) return fail("record_checkpoint_tenant_mismatch", "the checkpoint and the event name different workspaces");
  if (!cp.signature) return fail("record_checkpoint_unsigned", "the checkpoint carries no signature");
  let sigRaw, signedBytes;
  try {
    sigRaw = derToRawEcdsa(b64ToBytes(cp.signature), 48);
    signedBytes = recordCheckpointSignedPayload(cp);
  } catch (e) {
    return fail("record_signature_verification_error", String(e.message || e));
  }
  trustedKeys = trustedKeys || [];
  if (trustedKeys.length) {
    // Verify against the PINNED trust anchor, never the checkpoint's key.
    const matched = await verifySigAgainstTrusted(sigRaw, signedBytes, trustedKeys);
    if (!matched) return fail("record_checkpoint_key_untrusted", "the checkpoint signature does not verify against any PINNED Kanonik key: re-signed with a foreign key, tampered, or a key not yet pinned. The checkpoint's own signing_public_key_pem is intentionally NOT trusted.");
    if (matched.class === "sample") return rec("record_checkpoint_signature", "DEGRADED", [SAMPLE_KEY_NOTE]);
    if ((matched.env || "") === "production") {
      return rec("record_checkpoint_signature", "PASS", [`ECDSA P-384 + SHA-384 signature verified against Kanonik's PINNED PRODUCTION key (id ${JSON.stringify(matched.signing_key_id || "")}); record attested by Kanonik at ${cp.signed_at}`]);
    }
    const label = matched.label || matched.env || "non-production";
    return rec("record_checkpoint_signature", "DEGRADED", [`signature verified against a pinned NON-PRODUCTION Kanonik key (env=${matched.env || "dev"}, ${label}); the record is structurally sound but is NOT attestable to Kanonik's PRODUCTION key.`]);
  }
  // No pinned trust anchor: fall back to the checkpoint's own key, DEGRADED.
  let pem;
  try {
    pem = new TextDecoder().decode(b64ToBytes(cp.signing_public_key_pem || ""));
  } catch (e) {
    return fail("record_checkpoint_b64_invalid", `checkpoint public key is not valid base64: ${e.message || e}`);
  }
  if (!pem.trim()) return fail("record_public_key_missing", "no pinned trust anchor and the checkpoint carries no signing public key");
  try {
    const key = await globalThis.crypto.subtle.importKey("spki", pemToDer(pem), { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
    const ok = await globalThis.crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, sigRaw, signedBytes);
    if (!ok) return fail("record_signature_verification_failed", "ECDSA P-384 + SHA-384 signature does NOT verify over the checkpoint (tampered, forged, or the wrong key)");
  } catch (e) {
    return fail("record_signature_verification_error", String(e.message || e));
  }
  return rec("record_checkpoint_signature", "DEGRADED", ["no pinned Kanonik trust anchor was available, so the checkpoint signature was verified only against the key the proof carries; that is not an independent check."]);
}

function checkRecordVerdict(proof) {
  const ev = proof.event && typeof proof.event === "object" ? proof.event : {};
  const kind = proof.kind || ev.entity_type || "";
  const payload = decodePayload(ev);
  const verdict = payload.verifier_verdict;
  if (RECORD_RULE_TIER_ONLY_KINDS.has(kind)) {
    const notes = [`a ${kind} is checked by the rule tier at the seal and carries no model verdict by design`];
    if (verdict) notes.push("a verdict is present anyway; not required");
    return rec("record_verdict", "PASS", notes);
  }
  if (!verdict || typeof verdict !== "object") return rec("record_verdict", "FAIL", [], [{ kind: "record_verdict_missing", message: `a sealed ${kind || "record"} must carry its verifier verdict; none is embedded` }]);
  const anomalies = [];
  const notes = [];
  const outcome = String(verdict.outcome || "").toLowerCase();
  if (outcome !== "approved") anomalies.push({ kind: "record_verdict_not_approved", message: `the embedded verdict outcome is ${JSON.stringify(outcome || "absent")}, not approved` });
  const meta = verdict.metadata && typeof verdict.metadata === "object" ? verdict.metadata : {};
  const missing = RECORD_VERDICT_REQUIRED.filter((k) => !meta[k]);
  if (missing.length) anomalies.push({ kind: "record_verdict_tuple_incomplete", message: "the verdict lacks replay fields: " + missing.join(", ") });
  if (!meta.canonical_inputs_hash) notes.push("canonical_inputs_hash absent: the inputs cannot be matched byte for byte against the record");
  const stated = proof.verdict && typeof proof.verdict === "object" ? proof.verdict : null;
  if (stated && meta.prompt_content_hash && stated.prompt_hash && stated.prompt_hash !== meta.prompt_content_hash) anomalies.push({ kind: "record_verdict_summary_mismatch", message: "the file's verdict summary names a different prompt hash than the sealed event" });
  if (!anomalies.length) notes.push(`verdict approved by ${meta.model_provider}/${meta.model} under prompt ${meta.prompt_version}`);
  return rec("record_verdict", anomalies.length ? "FAIL" : "PASS", notes, anomalies);
}

function checkRecordApproval(proof) {
  const ev = proof.event && typeof proof.event === "object" ? proof.event : {};
  const kind = proof.kind || ev.entity_type || "";
  const payload = decodePayload(ev);
  if (!payload.approved_by_subject || !payload.committed_at) return rec("record_approval", "FAIL", [], [{ kind: "record_approval_missing", message: "the sealed event names no approver or no seal time" }]);
  const approval = proof.approval && typeof proof.approval === "object" ? proof.approval : {};
  const anomalies = [];
  const notes = [];
  let status = "PASS";
  if (approval.approved_by_subject && approval.approved_by_subject !== payload.approved_by_subject) anomalies.push({ kind: "record_approver_mismatch", message: "the file's approval names a different approver than the sealed event" });
  const basis = approval.decision_basis || "";
  if (!basis) {
    status = "DEGRADED";
    notes.push("no approval event is attached, so the decision basis (why one person could seal) is not shown; the seal itself is in the sealed event");
  } else if (!RECORD_KNOWN_DECISION_BASES.has(basis)) anomalies.push({ kind: "record_decision_basis_unknown", message: `decision_basis ${JSON.stringify(basis)} is not one this verifier knows` });
  else if (basis === "author_self_seal_record_kind" && !RECORD_CATALOGUE_SELF_SEAL.has(kind)) anomalies.push({ kind: "record_self_seal_kind_not_allowed", message: `a ${kind} is not a kind its author may seal alone under the catalogue default` });
  if (anomalies.length) status = "FAIL";
  if (status === "PASS") notes.push(`sealed by ${payload.approved_by_subject} at ${payload.committed_at}; basis ${basis}`);
  return rec("record_approval", status, notes, anomalies);
}

function checkRecordCurrency(proof) {
  if (proof.is_latest_for_entity === true) return rec("record_currency", "PASS", [`latest sealed version as of ${proof.exported_at}`]);
  const newer = proof.latest_canonical_id || "a later version";
  return rec("record_currency", "DEGRADED", [`a newer sealed version (${newer}) existed when this file was made on ${proof.exported_at}; this record verifies as the version it is, not as the current one. Ask the sender for the current file.`]);
}

// verifyRecordProof takes the parsed proof-<kind>-<id>.json and returns the
// same summary shape verify.py --record prints on stdout.
export async function verifyRecordProof(proof, opts = {}) {
  if (!proof || typeof proof !== "object") throw new Error("the proof file is not a JSON object");
  const trustedKeys = [...DEFAULT_TRUSTED_KEYS, ...(opts.trustedKeys || [])];
  const results = [
    checkRecordSchema(proof),
    await checkRecordEventHash(proof),
    await checkRecordCheckpointSignature(proof, trustedKeys),
    checkRecordVerdict(proof),
    checkRecordApproval(proof),
    checkRecordCurrency(proof),
  ];
  const byStatus = { PASS: 0, FAIL: 0, DEGRADED: 0 };
  for (const r of results) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
  const overall = byStatus.FAIL > 0 ? "FAIL" : byStatus.DEGRADED > 0 ? "DEGRADED" : "PASS";
  return {
    schema_version: "v1",
    verifier_version: VERIFIER_VERSION,
    mode: "record",
    record: { kind: proof.kind, canonical_id: proof.canonical_id, exported_at: proof.exported_at },
    overall_status: overall,
    summary: byStatus,
    checks: results,
  };
}

// ── disclosure file (`--disclosure`, mirror verify.py run_disclosure_checks) ─────────────────────────────────
//
// {manifest, signature: {version, manifest_sha384, value}}. The chain-root key signed the canonical JSON of
// {version: "disclosure-v1", manifest_sha384, publisher_public_id, issued_at, key_id}. This checker re-derives the
// digest and the signing input from the manifest in the file, picks the pinned key by the manifest's key_id and
// never trusts a key the file carries. Outcomes: VERIFIED, VERIFIED_NON_PRODUCTION, UNKNOWN_ISSUER (key id not
// pinned), BAD_SIGNATURE (pinned id, signature does not verify), KEY_REVOKED, UNKNOWN_SCHEMA, VERIFIER_TOO_OLD,
// MALFORMED. HONEST LIMIT: it shows Kanonik attested the text was approved and sealed in the named event and is
// unchanged since; it cannot recompute that event's hash and never says the text is true.

const DISCLOSURE_MANIFEST_SCHEMA = "kanonik-disclosure/v1";
const DISCLOSURE_SIGNATURE_VERSION = "disclosure-v1";
const DISCLOSURE_CONSUMER_VERSION = 1;
const KEY_FILE_SCHEMA_V1 = "kanonik-chain-root-keys/v1";
const KEY_FILE_SCHEMA_V2 = "kanonik-chain-root-keys/v2";
const KEY_STATUS_RANK = { active: 0, retired: 1, revoked: 2 };
const DISCLOSURE_RECORD_STATUSES = ["current", "needs_review", "superseded", "retired", "unknown"];
const DISCLOSURE_ACCESS_STATES = ["active", "revoked", "expired", "unknown"];
const DISCLOSURE_STATUS_HOSTS = ["kanonik.ai", "share.kanonik.ai"];
const DISCLOSURE_STATUS_PATH = /^\/api\/v1\/public\/disclosures\/[A-Za-z0-9_-]+\/status$/;
export const WELL_KNOWN_KEYS_URL = "https://kanonik.ai/.well-known/kanonik-chain-root-keys.json";

// canonicalMarshal writes the UTF-8 bytes one character per byte (encStr), so the bytes are the char codes. A
// disclosure carries free text, so non-ASCII must not be encoded twice.
const canonicalBytes = (v) => Uint8Array.from(canonicalMarshal(v), (c) => c.charCodeAt(0));
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// A missing status is active (the v1 file); a word this checker does not know is read as revoked, so a newer file
// can never widen trust on an older checker.
function keyStatus(raw) {
  if (raw === undefined || raw === null || raw === "") return "active";
  return typeof raw === "string" && hasOwn(KEY_STATUS_RANK, raw) ? raw : "revoked";
}

const SPKI_CACHE = new Map();
// The identity of a public key: SHA-256 of its canonical (uncompressed) SubjectPublicKeyInfo. The key is imported and
// exported again, so the compressed and uncompressed encodings of one point get one identity, as in verify.py.
async function spkiSha256(pem) {
  const text = typeof pem === "string" ? pem : new TextDecoder().decode(pem || new Uint8Array(0));
  if (SPKI_CACHE.has(text)) return SPKI_CACHE.get(text);
  let out = "";
  try {
    const der = pemToDer(text);
    try {
      const key = await globalThis.crypto.subtle.importKey("spki", der, { name: "ECDSA", namedCurve: "P-384" }, true, ["verify"]);
      out = hex(await sha256(new Uint8Array(await globalThis.crypto.subtle.exportKey("spki", key))));
    } catch {
      out = ""; // not a P-384 key this checker can use: it has no identity and vouches for nothing
    }
  } catch { /* not a key */ }
  SPKI_CACHE.set(text, out);
  return out;
}

async function keyEntry(k, status) {
  if (!isObj(k) || !k.pem || (typeof k.pem === "string" && !k.pem.trim())) return null;
  const pem = typeof k.pem === "string" ? k.pem : new TextDecoder().decode(k.pem);
  const text = (v) => (typeof v === "string" ? v : ""); // a value that is not text is no value (verify.py reads it the same way)
  return {
    signing_key_id: text(k.signing_key_id),
    env: text(k.env).toLowerCase(),
    class: text(k.class),
    label: text(k.label),
    seal_required_from: text(k.seal_required_from),
    pem,
    sha256_spki_der: await spkiSha256(pem), // derived from the key; a fingerprint the entry claims is never used
    status: status !== undefined ? status : keyStatus(k.status),
  };
}

// Give every entry for the same public key (same SPKI hash) the strongest status any of them has, so a revocation
// cannot be dodged by listing the key twice. Returns copies. Mirrors verify.py _consolidate_keys.
async function consolidateKeys(keys) {
  const spkis = [];
  const worst = new Map();
  for (const k of keys) {
    // Identity comes from the key itself, never from a fingerprint the entry claims for it.
    const s = await spkiSha256(k.pem);
    spkis.push(s);
    if (s) worst.set(s, Math.max(worst.get(s) || 0, KEY_STATUS_RANK[keyStatus(k.status)]));
  }
  const names = Object.keys(KEY_STATUS_RANK);
  return keys.map((k, i) => ({ ...k, status: spkis[i] ? names[worst.get(spkis[i])] : keyStatus(k.status) }));
}

// What in a manifest cannot be put in canonical form the same way in every checker: a number that is not a whole
// number within +-(2^53-1) (JSON.parse has already rounded the rest), an unpaired surrogate (TextEncoder would
// replace it), or nesting deep enough to be an attack. Mirrors verify.py _unrepresentable.
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
function unrepresentable(v, depth = 0) {
  if (depth > 64) return "nesting deeper than 64 levels";
  if (v === null || typeof v === "boolean") return null;
  if (typeof v === "string") return LONE_SURROGATE.test(v) ? "an unpaired surrogate in a string" : null;
  if (typeof v === "number") {
    if (!Number.isInteger(v)) return "a number that is not a whole number";
    return Math.abs(v) > Number.MAX_SAFE_INTEGER ? "a number beyond 2^53-1" : null;
  }
  if (Array.isArray(v)) {
    for (const x of v) {
      const r = unrepresentable(x, depth + 1);
      if (r) return r;
    }
    return null;
  }
  if (typeof v === "object") {
    for (const k of Object.keys(v)) {
      const r = unrepresentable(k, depth + 1) || unrepresentable(v[k], depth + 1);
      if (r) return r;
    }
    return null;
  }
  return "a value that is not JSON";
}

async function verifyKeyFileContinuity(pinned, doc) {
  const cont = doc.continuity;
  if (!isObj(cont)) return [false, "the key file carries no continuity signature"];
  if (typeof cont.signed_by !== "string" || typeof cont.signature !== "string" || typeof cont.signed_at !== "string") return [false, "the continuity block is incomplete"];
  const signer = pinned.find((k) => k.sha256_spki_der === cont.signed_by);
  if (!signer) return [false, "the continuity signer is not a pinned key"];
  if (signer.env !== "production" || signer.class === "sample") return [false, "the continuity signer is not a pinned production key"];
  if (signer.status === "revoked") return [false, "the continuity signer is revoked"];
  if (unrepresentable(doc)) return [false, "the key file holds a value this checker cannot read the same way as another checker"];
  try {
    // Own properties are copied by definition, not assignment: a signed key named "__proto__" must stay a key.
    const body = Object.fromEntries(Object.entries(doc).filter(([k]) => k !== "continuity"));
    Object.defineProperty(body, "continuity", { value: Object.fromEntries(Object.entries(cont).filter(([k]) => k !== "signature")), enumerable: true, writable: true, configurable: true });
    const key = await globalThis.crypto.subtle.importKey("spki", pemToDer(signer.pem), { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
    const ok = await globalThis.crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, derToRawEcdsa(strictRootB64(cont.signature), 48), canonicalBytes(body));
    if (!ok) return [false, "the continuity signature does not verify"];
  } catch {
    return [false, "the continuity signature does not verify"];
  }
  return [true, ""];
}

const SIGNED_AT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const SPKI_HEX = /^[0-9a-f]{64}$/;

// The SPKI hashes a key file lists under `revoked_keys`. That field is separate from `keys` on purpose: checkers up to
// 2.7.18 add every key in `keys` that has a PEM and ignore its status, so a revoked key is never published there.
function revokedSpkis(doc) {
  const raw = isObj(doc) ? doc.revoked_keys : undefined;
  if (!Array.isArray(raw)) return [];
  return raw.filter((e) => isObj(e) && typeof e.sha256_spki_der === "string" && SPKI_HEX.test(e.sha256_spki_der)).map((e) => e.sha256_spki_der);
}

function applyRevoked(keys, doc) {
  const gone = new Set(revokedSpkis(doc));
  return gone.size ? keys.map((k) => (gone.has(k.sha256_spki_der) ? { ...k, status: "revoked" } : k)) : keys;
}

// The floor the shipped key file carries: the earliest signing time of an online key file this checker accepts.
export const MIN_KEY_FILE_SIGNED_AT = "2026-10-24T00:00:00Z";

// mergeKeyFile folds a key file fetched from the well-known address into the pinned set. Returns {keys, mode, note}.
//  continuity: a v2 file a pinned production key signed, no earlier than minSignedAt (so an older signed file cannot
//    be served again). May add keys (a new production key too) and move a known key's status forward (active ->
//    retired -> revoked, also through revoked_keys), never back.
//  rejected: anything else, an unsigned file or a v1 file included. Takes nothing: an unsigned file is exactly what
//    a tampered www deploy would serve (a tampered web deploy adding a trusted key).
// The pinned set always wins: nothing here removes a pinned key or changes its public key.
export async function mergeKeyFile(pinnedIn, doc, minSignedAt = "") {
  const pinnedRaw = [];
  for (const k of pinnedIn) {
    const e = await keyEntry(k, keyStatus(k.status));
    if (e) pinnedRaw.push(e);
  }
  const pinned = await consolidateKeys(pinnedRaw);
  if (!isObj(doc) || (hasOwn(doc, "keys") && !Array.isArray(doc.keys))) return { keys: pinned, mode: "rejected", note: "the online key file is not a key file" };
  if (doc.schema !== KEY_FILE_SCHEMA_V2) {
    if (doc.schema === KEY_FILE_SCHEMA_V1 || doc.schema === undefined || doc.schema === null) return { keys: pinned, mode: "rejected", note: "the online key file is not signed (no v2 schema): nothing was taken from it" };
    return { keys: pinned, mode: "rejected", note: `the online key file names a schema this checker does not read: ${JSON.stringify(doc.schema)}` };
  }
  const [ok, why] = await verifyKeyFileContinuity(pinned, doc);
  if (!ok) return { keys: pinned, mode: "rejected", note: `the online key file was not used: ${why}` };
  if (minSignedAt) {
    const at = doc.continuity.signed_at;
    if (typeof at !== "string" || !SIGNED_AT.test(at)) return { keys: pinned, mode: "rejected", note: "the online key file was not used: its signing time is not in the form YYYY-MM-DDTHH:MM:SSZ" };
    if (at < minSignedAt) return { keys: pinned, mode: "rejected", note: `the online key file was not used: it was signed ${at}, before ${minSignedAt}, the earliest this checker accepts (an old file served again)` };
  }
  const out = pinned.map((k) => ({ ...k }));
  const bySpki = new Map(out.map((k) => [k.sha256_spki_der, k]));
  for (const raw of doc.keys || []) {
    const entry = await keyEntry(raw);
    if (!entry || !entry.sha256_spki_der) continue;
    const have = bySpki.get(entry.sha256_spki_der);
    if (have) {
      if (KEY_STATUS_RANK[entry.status] > KEY_STATUS_RANK[have.status]) have.status = entry.status;
      continue;
    }
    out.push(entry);
    bySpki.set(entry.sha256_spki_der, entry);
  }
  return { keys: await consolidateKeys(applyRevoked(out, doc)), mode: "continuity", note: "" };
}

// Only https://kanonik.ai or https://share.kanonik.ai, default port, no credentials, the public status path and
// no query: the address comes from the file under test, so it is never fetched anywhere else.
export function disclosureStatusUrlAllowed(url) {
  if (typeof url !== "string" || !url || /[\u0000-\u0020\u007f\\]/.test(url)) return false;
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  return u.protocol === "https:" && DISCLOSURE_STATUS_HOSTS.includes(u.hostname) && u.port === "" && u.username === "" && u.password === "" &&
    u.search === "" && u.hash === "" && DISCLOSURE_STATUS_PATH.test(u.pathname) && !/[?#]/.test(url) && url.indexOf("//" + u.hostname + "/") === url.indexOf("//");
}

// fetchDisclosureStatus reads the public status endpoint; null on a disallowed address or any failure (the report
// then says the status is unknown).
export async function fetchDisclosureStatus(url, fetchImpl = globalThis.fetch) {
  if (!disclosureStatusUrlAllowed(url) || typeof fetchImpl !== "function") return null;
  try {
    const resp = await fetchImpl(url, { headers: { Accept: "application/json" }, credentials: "omit", redirect: "error" });
    if (!resp.ok) return null;
    return JSON.parse(await resp.text());
  } catch {
    return null;
  }
}

function checkDisclosureStatus(requested, response) {
  const info = { record_status: "unknown", access_state: "unknown", checked: !!requested, as_of: "" };
  const notes = [];
  if (!requested) {
    notes.push("status not checked (offline). Run again with --online to ask Kanonik whether this is still current and still shared.");
    return [rec("disclosure_status", "PASS", notes), info];
  }
  const ok = isObj(response);
  const rs = ok ? response.record_status : null;
  const acc = ok ? response.access_state : null;
  info.record_status = typeof rs === "string" && DISCLOSURE_RECORD_STATUSES.includes(rs) ? rs : "unknown";
  info.access_state = typeof acc === "string" && DISCLOSURE_ACCESS_STATES.includes(acc) ? acc : "unknown";
  if (ok && typeof response.as_of === "string") info.as_of = response.as_of;
  if (info.record_status === "current" && info.access_state === "active") {
    notes.push(`status: current, access active (as of ${info.as_of || "now"})`);
    return [rec("disclosure_status", "PASS", notes), info];
  }
  if (info.record_status === "unknown" || info.access_state === "unknown") notes.push("status unknown, integrity as shown: the signature result above stands, but whether this is still current and still shared could not be read.");
  if (info.record_status !== "current" && info.record_status !== "unknown") notes.push(`the record is ${info.record_status.replace(/_/g, " ")}: it was approved when issued and has changed since.`);
  if (info.access_state === "revoked" || info.access_state === "expired") notes.push(`access is ${info.access_state}: this copy was issued legitimately and has since been withdrawn from sharing.`);
  return [rec("disclosure_status", "DEGRADED", notes), info];
}

const discFail = (check, kind, message) => rec(check, "FAIL", [], [{ kind, message }]);

async function sha384Hex(bytes) {
  return hex(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-384", bytes)));
}

// runDisclosureChecks returns {outcome, checks, status}. opts: {status: {requested, response}}.
async function runDisclosureChecks(doc, trustedKeys, opts = {}) {
  const statusRequested = !!(opts.status && opts.status.requested);
  const statusResponse = opts.status ? opts.status.response : null;
  let info = { record_status: "unknown", access_state: "unknown", checked: false, as_of: "" };
  const SCHEMA = "disclosure_schema_and_version";
  const early = (outcome, check) => ({ outcome, checks: [check], status: info });
  if (!isObj(doc) || !isObj(doc.manifest) || !isObj(doc.signature)) return early("MALFORMED", discFail(SCHEMA, "disclosure_malformed", "this is not a disclosure file: it needs a manifest and a signature block"));
  const m = doc.manifest;
  const sig = doc.signature;
  if (m.schema !== DISCLOSURE_MANIFEST_SCHEMA) return early("UNKNOWN_SCHEMA", discFail(SCHEMA, "disclosure_schema_unknown", `the manifest schema is ${pyRepr(m.schema)}; this checker reads ${DISCLOSURE_MANIFEST_SCHEMA}. Refused, not guessed.`));
  if (sig.version !== DISCLOSURE_SIGNATURE_VERSION) return early("UNKNOWN_SCHEMA", discFail(SCHEMA, "disclosure_signature_version_unknown", `the signature version is ${pyRepr(sig.version)}; this checker reads ${DISCLOSURE_SIGNATURE_VERSION}`));
  const minimum = m.min_verifier_version;
  const cons = m.min_consumer_version;
  if (typeof minimum !== "string" || !minimum || typeof cons !== "number" || !Number.isInteger(cons)) return early("MALFORMED", discFail(SCHEMA, "disclosure_version_fields_missing", "the manifest names no minimum checker version or consumer version"));
  if (versionGreater(minimum, VERIFIER_VERSION)) return early("VERIFIER_TOO_OLD", discFail(SCHEMA, "disclosure_verifier_too_old", `the file needs checker ${minimum} or later; this is ${VERIFIER_VERSION}. Get the current checker from kanonik.ai/verify.`));
  if (cons > DISCLOSURE_CONSUMER_VERSION) return early("VERIFIER_TOO_OLD", discFail(SCHEMA, "disclosure_consumer_too_new", `the file needs consumer version ${cons}; this checker reads ${DISCLOSURE_CONSUMER_VERSION}. Get the current checker from kanonik.ai/verify.`));
  const keyId = m.key_id;
  const pubId = isObj(m.publisher) ? m.publisher.public_id : null;
  const issued = m.issued_at;
  const digestStated = sig.manifest_sha384;
  if (![keyId, pubId, issued, digestStated].every((x) => typeof x === "string" && x) || typeof sig.value !== "string") return early("MALFORMED", discFail(SCHEMA, "disclosure_malformed", "the manifest or signature block is missing a field the signature covers (key_id, publisher, issued_at, digest, value)"));

  const bad = unrepresentable(m);
  if (bad) return early("MALFORMED", discFail(SCHEMA, "disclosure_value_unrepresentable", `the manifest holds ${bad}; this checker refuses it rather than read it differently from another checker`));

  const checks = [];
  checks.push(rec(SCHEMA, "PASS", [`${DISCLOSURE_MANIFEST_SCHEMA}, signature ${DISCLOSURE_SIGNATURE_VERSION}; the file needs checker ${minimum}, this is ${VERIFIER_VERSION}`]));
  const finish = (outcome, sigCheck) => {
    checks.push(sigCheck);
    if (outcome.startsWith("VERIFIED")) {
      const [st, stInfo] = checkDisclosureStatus(statusRequested, statusResponse);
      checks.push(st);
      info = stInfo;
    }
    return { outcome, checks, status: info };
  };
  const SIG = "disclosure_signature";
  trustedKeys = await consolidateKeys(trustedKeys || []);
  const candidates = trustedKeys.filter((k) => k.signing_key_id === keyId);
  if (!candidates.length) return finish("UNKNOWN_ISSUER", discFail(SIG, "disclosure_issuer_unknown", `the file was signed with key ${pyRepr(keyId)}, which this checker does not pin. The file is not shown to be forged: this checker may be older than the key. Get the current checker from kanonik.ai/verify, or run again with --online.`));

  let digest;
  try {
    digest = await sha384Hex(canonicalBytes(m));
  } catch (e) {
    return finish("MALFORMED", discFail(SIG, "disclosure_manifest_unreadable", `the manifest cannot be put in canonical form: ${e.message || e}`));
  }
  if (digest !== digestStated) return finish("BAD_SIGNATURE", discFail(SIG, "disclosure_manifest_changed", "the manifest is not the one that was signed: its digest differs from the signed digest (changed after signing, or damaged)"));

  let signingInput, rawSig;
  try {
    signingInput = canonicalBytes({ version: DISCLOSURE_SIGNATURE_VERSION, manifest_sha384: digest, publisher_public_id: pubId, issued_at: issued, key_id: keyId });
    rawSig = derToRawEcdsa(strictRootB64(sig.value), 48);
  } catch {
    return finish("BAD_SIGNATURE", discFail(SIG, "disclosure_signature_unreadable", "the signature is empty or is not canonical base64"));
  }
  let matched = null;
  for (const k of candidates) {
    try {
      const key = await globalThis.crypto.subtle.importKey("spki", pemToDer(typeof k.pem === "string" ? k.pem : new TextDecoder().decode(k.pem)), { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
      if (await globalThis.crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, rawSig, signingInput)) {
        matched = k;
        break;
      }
    } catch { /* try the next pinned key with this id */ }
  }
  if (!matched) return finish("BAD_SIGNATURE", discFail(SIG, "disclosure_signature_invalid", `the signature does not verify under any pinned key with id ${pyRepr(keyId)}: signed by another key, or changed after signing`));
  if (matched.status === "revoked") return finish("KEY_REVOKED", discFail(SIG, "disclosure_key_revoked", `the key ${pyRepr(keyId)} that signed this file has been revoked by Kanonik. Do not rely on it.`));

  const items = m.items;
  if (!Array.isArray(items) || !items.length) return finish("MALFORMED", discFail(SIG, "disclosure_items_missing", "the signed manifest carries no items"));
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    const text = isObj(it) ? it.text : null;
    if (typeof text !== "string" || it.text_sha256 !== hex(await sha256(te.encode(text)))) return finish("MALFORMED", discFail(SIG, "disclosure_item_hash_mismatch", `item ${i}'s stated hash is not the hash of its text`));
  }
  const notes = [];
  let status = "PASS";
  let outcome;
  const env = matched.env || "";
  if (matched.class === "sample") {
    status = "DEGRADED";
    notes.push(SAMPLE_KEY_NOTE);
    outcome = "VERIFIED_NON_PRODUCTION";
  } else if (env === "production") {
    outcome = "VERIFIED";
    notes.push(`ECDSA P-384 + SHA-384 signature verified against Kanonik's PINNED PRODUCTION key (id ${pyRepr(keyId)}); issued ${issued}`);
    if (matched.status === "retired") notes.push("that key is retired: it no longer signs, and a file it signed while active still verifies.");
  } else {
    status = "DEGRADED";
    outcome = "VERIFIED_NON_PRODUCTION";
    notes.push(`signature verified against a pinned NON-PRODUCTION Kanonik key (env=${env || "dev"}); the file is structurally sound but is NOT attestable to Kanonik's PRODUCTION key. Expected for integration/dev files.`);
  }
  notes.push("What this shows: Kanonik attested that this text was approved and sealed in the named event, and it is unchanged since. It does not show the text is true, and this checker cannot recompute that event's hash.");
  const r = rec(SIG, status, notes, [], items.length);
  return finish(outcome, r);
}

// Python's repr of a string, so the two checkers print the same words.
function pyRepr(v) {
  if (typeof v !== "string") return v === null || v === undefined ? "None" : JSON.stringify(v);
  return v.includes("'") && !v.includes('"') ? JSON.stringify(v) : "'" + v.replace(/\\/g, "\\\\").replace(/'/g, "\\'") + "'";
}

// verifyDisclosure takes the parsed disclosure file and returns the same summary shape verify.py --disclosure prints
// on stdout. opts: {trustedKeys (added to the shipped set), pinned (replaces it, for tests), status: {requested,
// response}}.
export async function verifyDisclosure(doc, opts = {}) {
  const trustedKeys = [];
  for (const k of opts.pinned || [...DEFAULT_TRUSTED_KEYS, ...(opts.trustedKeys || [])]) {
    const e = await keyEntry(k, keyStatus(k.status));
    if (e) trustedKeys.push(e);
  }
  const { outcome, checks, status } = await runDisclosureChecks(doc, trustedKeys, opts);
  const byStatus = { PASS: 0, FAIL: 0, DEGRADED: 0 };
  for (const r of checks) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
  const overall = byStatus.FAIL > 0 ? "FAIL" : byStatus.DEGRADED > 0 ? "DEGRADED" : "PASS";
  const m = isObj(doc) && isObj(doc.manifest) ? doc.manifest : {};
  const pub = isObj(m.publisher) ? m.publisher : {};
  return {
    schema_version: "v1",
    verifier_version: VERIFIER_VERSION,
    mode: "disclosure",
    outcome,
    status,
    // What the file says about itself is returned only when the signature held: otherwise it is unverified text.
    disclosure: outcome.startsWith("VERIFIED") ? { disclosure_id: m.disclosure_id, publisher: pub.label, issued_at: m.issued_at, expires_at: m.expires_at, check_code: m.check_code, subject: isObj(m.subject_ref) ? m.subject_ref.title : null } : {},
    overall_status: overall,
    summary: byStatus,
    checks,
  };
}

// ── trust feed (`--feed`, mirror verify.py run_feed_checks) ─────────────────────────────────────────
//
// {feed, signature: {version, feed_sha384, value}}. The chain-root key signed the canonical JSON of
// {version: "trust-feed-v1", feed_sha384, publisher_public_id, issued_at, key_id}, built the way disclosure-v1 is.
// The digest and signing input are re-derived from the feed in the file; the key is picked by feed.key_id from the
// pinned set. Outcomes: the --disclosure words plus STALE (good signature, this checker's clock is past valid_until).
// A file over 1 MiB is refused before it is parsed. Every object refuses members the schema does not list.

const FEED_SCHEMA = "kanonik-trust-feed/v1";
const FEED_SIGNATURE_VERSION = "trust-feed-v1";
const FEED_CONSUMER_VERSION = 1;
export const FEED_MAX_BYTES = 1048576;
const FEED_HOSTS = ["share.kanonik.ai"];
const FEED_PATH = /^\/t\/[a-z0-9](?:[a-z0-9]|-(?!-)){1,38}[a-z0-9]\/feed\.json$/;
export const FEED_NOT_PUBLISHED = "the company no longer publishes this page";
const feedStaleMessage = (issuedAt) => `This copy was correct on ${issuedAt}. It is too old to rely on; fetch the current one.`;
const FEED_SCHEMA_DOC = JSON.parse("{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"$id\":\"https://kanonik.ai/schemas/trust-feed/v1.json\",\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"feed\",\"signature\"],\"properties\":{\"feed\":{\"$ref\":\"#/$defs/feed\"},\"signature\":{\"$ref\":\"#/$defs/signature\"}},\"$defs\":{\"slug\":{\"type\":\"string\",\"pattern\":\"^[a-z0-9](?:[a-z0-9]|-(?!-)){1,38}[a-z0-9]$\"},\"publicId\":{\"type\":\"string\",\"pattern\":\"^[A-Za-z0-9_-]{21}[AQgw]$\"},\"checkCode\":{\"type\":\"string\",\"pattern\":\"^[2-9A-HJKMNP-TW-Z]{4}(-[2-9A-HJKMNP-TW-Z]{4}){3}$\"},\"sha384\":{\"type\":\"string\",\"pattern\":\"^[0-9a-f]{96}$\"},\"sha256\":{\"type\":\"string\",\"pattern\":\"^[0-9a-f]{64}$\"},\"utcTime\":{\"type\":\"string\",\"pattern\":\"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$\"},\"utcDate\":{\"type\":\"string\",\"pattern\":\"^[0-9]{4}-[0-9]{2}-[0-9]{2}$\"},\"httpsUrl\":{\"type\":\"string\",\"maxLength\":300,\"pattern\":\"^https://[a-z0-9.-]+/\"},\"plainText\":{\"type\":\"string\",\"minLength\":1},\"signature\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"version\",\"feed_sha384\",\"value\"],\"properties\":{\"version\":{\"const\":\"trust-feed-v1\"},\"feed_sha384\":{\"$ref\":\"#/$defs/sha384\"},\"value\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":200,\"pattern\":\"^[A-Za-z0-9+/]+={0,2}$\"}}},\"feed\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schema\",\"feed_url\",\"page_url\",\"publisher\",\"issued_at\",\"valid_until\",\"key_id\",\"min_consumer_version\",\"min_verifier_version\",\"profile\",\"items\",\"statement\"],\"properties\":{\"schema\":{\"const\":\"kanonik-trust-feed/v1\"},\"feed_url\":{\"allOf\":[{\"$ref\":\"#/$defs/httpsUrl\"}],\"pattern\":\"^https://[a-z0-9.-]+/t/[a-z0-9][a-z0-9-]{1,38}[a-z0-9]/feed\\\\.json$\"},\"page_url\":{\"allOf\":[{\"$ref\":\"#/$defs/httpsUrl\"}],\"pattern\":\"^https://[a-z0-9.-]+/t/[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$\"},\"publisher\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"public_id\",\"label\"],\"properties\":{\"public_id\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[a-z0-9-]+$\"},\"label\":{\"allOf\":[{\"$ref\":\"#/$defs/plainText\"}],\"maxLength\":200}}},\"issued_at\":{\"$ref\":\"#/$defs/utcTime\"},\"valid_until\":{\"$ref\":\"#/$defs/utcTime\"},\"key_id\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9._/-]+$\"},\"min_consumer_version\":{\"type\":\"integer\",\"minimum\":1},\"min_verifier_version\":{\"type\":\"string\",\"pattern\":\"^[0-9]+\\\\.[0-9]+\\\\.[0-9]+$\"},\"profile\":{\"$ref\":\"#/$defs/profile\"},\"items\":{\"type\":\"array\",\"maxItems\":40,\"items\":{\"$ref\":\"#/$defs/item\"}},\"statement\":{\"allOf\":[{\"$ref\":\"#/$defs/plainText\"}],\"maxLength\":600}}},\"profile\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"public_id\",\"manifest_sha384\",\"disclosure_url\",\"legal_name\",\"display_name\",\"security_contact\",\"proved_domain\"],\"properties\":{\"public_id\":{\"$ref\":\"#/$defs/publicId\"},\"manifest_sha384\":{\"$ref\":\"#/$defs/sha384\"},\"disclosure_url\":{\"allOf\":[{\"$ref\":\"#/$defs/httpsUrl\"}],\"pattern\":\"^https://[a-z0-9.-]+/api/v1/public/disclosures/[A-Za-z0-9_-]{21}[AQgw]$\"},\"legal_name\":{\"allOf\":[{\"$ref\":\"#/$defs/plainText\"}],\"maxLength\":200},\"display_name\":{\"allOf\":[{\"$ref\":\"#/$defs/plainText\"}],\"maxLength\":200},\"intro\":{\"allOf\":[{\"$ref\":\"#/$defs/plainText\"}],\"maxLength\":400},\"security_contact\":{\"type\":\"string\",\"maxLength\":254,\"pattern\":\"^[^@\\\\s<>\\\"]+@[a-z0-9.-]+\\\\.[a-z]{2,}$\"},\"proved_domain\":{\"type\":\"string\",\"maxLength\":253,\"pattern\":\"^[a-z0-9.-]+\\\\.[a-z]{2,}$\"}}},\"document\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"type\",\"issuer\",\"issue_date\",\"valid_until\"],\"properties\":{\"type\":{\"enum\":[\"pentest_letter\",\"pci_aoc\",\"insurance_certificate\"]},\"issuer\":{\"allOf\":[{\"$ref\":\"#/$defs/plainText\"}],\"maxLength\":200},\"issue_date\":{\"$ref\":\"#/$defs/utcDate\"},\"valid_until\":{\"$ref\":\"#/$defs/utcDate\"},\"file_sha256\":{\"$ref\":\"#/$defs/sha256\"}}},\"item\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"public_id\",\"family\",\"section\",\"title\",\"access\",\"record_status\",\"listed_since\",\"listed_until\",\"check_code\",\"check_url\",\"status_url\"],\"properties\":{\"public_id\":{\"$ref\":\"#/$defs/publicId\"},\"family\":{\"enum\":[\"answer_set\",\"policy\",\"procedure\",\"standing_summary\",\"subprocessor_list\",\"third_party_document\"]},\"section\":{\"enum\":[\"at_a_glance\",\"answers\",\"policies\",\"standing\",\"subprocessors\",\"documents\"]},\"title\":{\"allOf\":[{\"$ref\":\"#/$defs/plainText\"}],\"maxLength\":200},\"version\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":32},\"access\":{\"enum\":[\"open\",\"on_request\"]},\"record_status\":{\"enum\":[\"current\",\"needs_review\"]},\"approved_on\":{\"$ref\":\"#/$defs/utcDate\"},\"approved_by_titles\":{\"type\":\"array\",\"minItems\":1,\"maxItems\":5,\"items\":{\"allOf\":[{\"$ref\":\"#/$defs/plainText\"}],\"maxLength\":100}},\"review_due\":{\"$ref\":\"#/$defs/utcDate\"},\"listed_since\":{\"$ref\":\"#/$defs/utcTime\"},\"listed_until\":{\"$ref\":\"#/$defs/utcTime\"},\"check_code\":{\"$ref\":\"#/$defs/checkCode\"},\"check_url\":{\"type\":\"string\",\"pattern\":\"^https://[a-z0-9.-]+/verify\\\\?code=[2-9A-HJKMNP-TW-Z]{4}(-[2-9A-HJKMNP-TW-Z]{4}){3}$\"},\"status_url\":{\"type\":\"string\",\"pattern\":\"^https://[a-z0-9.-]+/api/v1/public/disclosures/[A-Za-z0-9_-]{21}[AQgw]/status$\"},\"manifest_sha384\":{\"$ref\":\"#/$defs/sha384\"},\"disclosure_url\":{\"type\":\"string\",\"pattern\":\"^https://[a-z0-9.-]+/api/v1/public/disclosures/[A-Za-z0-9_-]{21}[AQgw]$\"},\"item_url\":{\"type\":\"string\",\"pattern\":\"^https://[a-z0-9.-]+/d/[A-Za-z0-9_-]{21}[AQgw]$\"},\"request_url\":{\"type\":\"string\",\"pattern\":\"^https://[a-z0-9.-]+/t/[a-z0-9][a-z0-9-]{1,38}[a-z0-9]/request$\"},\"nda_required\":{\"type\":\"boolean\"},\"document\":{\"$ref\":\"#/$defs/document\"}},\"allOf\":[{\"if\":{\"properties\":{\"access\":{\"const\":\"open\"}}},\"then\":{\"required\":[\"manifest_sha384\",\"disclosure_url\",\"item_url\"],\"not\":{\"anyOf\":[{\"required\":[\"request_url\"]},{\"required\":[\"nda_required\"]}]}}},{\"if\":{\"properties\":{\"access\":{\"const\":\"on_request\"}}},\"then\":{\"required\":[\"request_url\",\"nda_required\"],\"not\":{\"anyOf\":[{\"required\":[\"manifest_sha384\"]},{\"required\":[\"disclosure_url\"]},{\"required\":[\"item_url\"]},{\"properties\":{\"document\":{\"required\":[\"file_sha256\"]}},\"required\":[\"document\"]}]}}},{\"if\":{\"properties\":{\"family\":{\"const\":\"third_party_document\"}}},\"then\":{\"required\":[\"document\"],\"properties\":{\"section\":{\"const\":\"documents\"}}},\"else\":{\"not\":{\"required\":[\"document\"]}}},{\"if\":{\"properties\":{\"section\":{\"const\":\"at_a_glance\"}}},\"then\":{\"properties\":{\"family\":{\"const\":\"answer_set\"},\"access\":{\"const\":\"open\"}}}}]}}}");
const UTC_TIME = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/;

// Epoch seconds of a YYYY-MM-DDTHH:MM:SSZ time, or null when it is not a real instant (verify.py agrees).
function utcSeconds(s) {
  const m = typeof s === "string" ? UTC_TIME.exec(s) : null;
  if (!m) return null;
  const [y, mo, d, h, mi, se] = m.slice(1).map(Number);
  if (y < 1000) return null;
  const t = Date.UTC(y, mo - 1, d, h, mi, se);
  const dt = new Date(t);
  if (Number.isNaN(t) || dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d || dt.getUTCHours() !== h || dt.getUTCMinutes() !== mi || dt.getUTCSeconds() !== se) return null;
  return Math.floor(t / 1000);
}

const FEED_REGEX_CACHE = new Map();
function feedRegex(pattern) {
  let re = FEED_REGEX_CACHE.get(pattern);
  if (!re) {
    // `\s` is spelled out so both checkers read it alike (JavaScript's covers more characters).
    re = new RegExp(pattern.replace(/\\s/g, " \\t\\n\\r\\f\\v"), "u");
    FEED_REGEX_CACHE.set(pattern, re);
  }
  return re;
}

function schemaKind(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return "boolean";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "other";
  if (typeof v === "string") return "string";
  if (Array.isArray(v)) return "array";
  if (typeof v === "object") return "object";
  return "other";
}

// A small JSON Schema reader for exactly the keywords the trust feed schema uses. Appends what is wrong to errs.
function schemaCheck(node, v, path, errs, limit = 5) {
  if (errs.length >= limit) return;
  const at = path || "/";
  if (hasOwn(node, "$ref")) {
    let target = FEED_SCHEMA_DOC;
    for (const part of node.$ref.replace(/^#\//, "").split("/")) target = target[part];
    schemaCheck(target, v, path, errs, limit);
  }
  const kind = schemaKind(v);
  const t = node.type;
  if (t !== undefined && !(kind === t || (t === "number" && kind === "integer"))) {
    errs.push(`${at}: expected ${t}, found ${kind}`);
    return;
  }
  if (hasOwn(node, "const") && (kind !== schemaKind(node.const) || v !== node.const)) errs.push(`${at}: not the expected value`);
  if (hasOwn(node, "enum") && !node.enum.some((e) => kind === schemaKind(e) && v === e)) errs.push(`${at}: not one of the allowed values`);
  if (kind === "string") {
    if (hasOwn(node, "pattern") && !feedRegex(node.pattern).test(v)) errs.push(`${at}: not in the required form`);
    const len = Array.from(v).length;
    if (hasOwn(node, "minLength") && len < node.minLength) errs.push(`${at}: too short`);
    if (hasOwn(node, "maxLength") && len > node.maxLength) errs.push(`${at}: too long`);
  }
  if (kind === "integer" && hasOwn(node, "minimum") && v < node.minimum) errs.push(`${at}: below the minimum`);
  if (kind === "array") {
    if (hasOwn(node, "minItems") && v.length < node.minItems) errs.push(`${at}: too few entries`);
    if (hasOwn(node, "maxItems") && v.length > node.maxItems) errs.push(`${at}: too many entries`);
    if (hasOwn(node, "items")) v.forEach((x, i) => schemaCheck(node.items, x, `${path}/${i}`, errs, limit));
  }
  if (kind === "object") {
    const props = node.properties || {};
    for (const r of node.required || []) if (!hasOwn(v, r)) errs.push(`${at}: the member ${pyRepr(r)} is missing`);
    if (node.additionalProperties === false) for (const k of Object.keys(v)) if (!hasOwn(props, k)) errs.push(`${at}: the member ${pyRepr(k)} is not part of this format`);
    for (const [k, sub] of Object.entries(props)) if (hasOwn(v, k)) schemaCheck(sub, v[k], `${path}/${k}`, errs, limit);
  }
  for (const sub of node.allOf || []) schemaCheck(sub, v, path, errs, limit);
  if (hasOwn(node, "anyOf") && !node.anyOf.some((sub) => !schemaErrors(sub, v).length)) errs.push(`${at}: matches none of the allowed shapes`);
  if (hasOwn(node, "not") && !schemaErrors(node.not, v).length) errs.push(`${at}: carries a member this kind of line must not carry`);
  if (hasOwn(node, "if")) {
    const branch = !schemaErrors(node.if, v).length ? node.then : node.else;
    if (branch !== undefined) schemaCheck(branch, v, path, errs, limit);
  }
}

function schemaErrors(node, v, path = "") {
  const errs = [];
  schemaCheck(node, v, path, errs);
  return errs;
}

export function feedShapeErrors(feed) {
  return schemaErrors(FEED_SCHEMA_DOC.$defs.feed, feed, "feed");
}

function ageWords(seconds) {
  const s = Math.max(0, Math.trunc(seconds));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const pl = (n, w) => `${n} ${w}${n !== 1 ? "s" : ""}`;
  if (d) return `${pl(d, "day")} ${pl(h, "hour")}`;
  if (h) return `${pl(h, "hour")} ${pl(m, "minute")}`;
  return pl(m, "minute");
}

// Only https://share.kanonik.ai/t/{slug}/feed.json, default port, no credentials, no query: the address comes from
// the file under test, so it is never fetched anywhere else.
export function feedUrlAllowed(url) {
  if (typeof url !== "string" || !url || /[\u0000-\u0020\u007f\\]/.test(url)) return false;
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  return u.protocol === "https:" && FEED_HOSTS.includes(u.hostname) && u.port === "" && u.username === "" && u.password === "" &&
    u.search === "" && u.hash === "" && FEED_PATH.test(u.pathname) && !/[?#]/.test(url) && url.indexOf("//" + u.hostname + "/") === url.indexOf("//");
}

// fetchLiveFeed reads the live feed. Returns {state: "ok", doc} | {state: "not_found"} | {state: "refused"} | {state: "error"}.
export async function fetchLiveFeed(url, fetchImpl = globalThis.fetch) {
  if (!feedUrlAllowed(url) || typeof fetchImpl !== "function") return { state: "refused" };
  try {
    const resp = await fetchImpl(url, { headers: { Accept: "application/json" }, credentials: "omit", redirect: "error" });
    if (resp.status === 404) return { state: "not_found" };
    if (!resp.ok) return { state: "error" };
    const reader = resp.body && resp.body.getReader ? resp.body.getReader() : null;
    let bytes;
    if (reader) {
      const parts = [];
      let n = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        n += value.length;
        if (n > FEED_MAX_BYTES) {
          try { await reader.cancel(); } catch { /* already closed */ }
          return { state: "error", reason: "too_large" };
        }
        parts.push(value);
      }
      bytes = concatBytes(parts);
    } else {
      bytes = new Uint8Array(await resp.arrayBuffer());
      if (bytes.length > FEED_MAX_BYTES) return { state: "error", reason: "too_large" };
    }
    return { state: "ok", doc: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) };
  } catch {
    return { state: "error" };
  }
}

export function feedItemRows(feed) {
  const keys = ["public_id", "title", "access", "record_status", "version", "check_code", "review_due", "listed_until"];
  const rows = [];
  for (const it of Array.isArray(feed.items) ? feed.items : []) {
    if (!isObj(it)) continue;
    const row = {};
    for (const k of keys) if (hasOwn(it, k)) row[k] = it[k];
    rows.push(row);
  }
  return rows;
}

const feedFail = (kind, message, check) => discFail(check || "feed_signature", kind, message);

// runFeedChecks returns {outcome, checks, info}. `now` is the checker's clock in epoch seconds (tests inject it).
async function runFeedChecks(doc, trustedKeys, now) {
  const info = {};
  const SCHEMA = "feed_schema_and_version";
  const early = (outcome, check) => ({ outcome, checks: [check], info });
  if (!isObj(doc) || !isObj(doc.feed) || !isObj(doc.signature)) return early("MALFORMED", feedFail("feed_malformed", "this is not a trust feed file: it needs a feed and a signature block", SCHEMA));
  if (Object.keys(doc).some((k) => k !== "feed" && k !== "signature")) return early("MALFORMED", feedFail("feed_unknown_member", "the file has a member outside feed and signature, which this format does not allow", SCHEMA));
  const f = doc.feed;
  const sig = doc.signature;
  if (f.schema !== FEED_SCHEMA) return early("UNKNOWN_SCHEMA", feedFail("feed_schema_unknown", `the feed schema is ${pyRepr(f.schema)}; this checker reads ${FEED_SCHEMA}. Refused, not guessed.`, SCHEMA));
  if (sig.version !== FEED_SIGNATURE_VERSION) return early("UNKNOWN_SCHEMA", feedFail("feed_signature_version_unknown", `the signature version is ${pyRepr(sig.version)}; this checker reads ${FEED_SIGNATURE_VERSION}`, SCHEMA));
  const minimum = f.min_verifier_version;
  const cons = f.min_consumer_version;
  if (typeof minimum !== "string" || !minimum || typeof cons !== "number" || !Number.isInteger(cons)) return early("MALFORMED", feedFail("feed_version_fields_missing", "the feed names no minimum checker version or consumer version", SCHEMA));
  if (versionGreater(minimum, VERIFIER_VERSION)) return early("VERIFIER_TOO_OLD", feedFail("feed_verifier_too_old", `the file needs checker ${minimum} or later; this is ${VERIFIER_VERSION}. Get the current checker from kanonik.ai/verify.`, SCHEMA));
  if (cons > FEED_CONSUMER_VERSION) return early("VERIFIER_TOO_OLD", feedFail("feed_consumer_too_new", `the file needs consumer version ${cons}; this checker reads ${FEED_CONSUMER_VERSION}. Get the current checker from kanonik.ai/verify.`, SCHEMA));
  const keyId = f.key_id;
  const pubId = isObj(f.publisher) ? f.publisher.public_id : null;
  const issued = f.issued_at;
  const digestStated = sig.feed_sha384;
  if (![keyId, pubId, issued, digestStated].every((x) => typeof x === "string" && x) || typeof sig.value !== "string") return early("MALFORMED", feedFail("feed_malformed", "the feed or signature block is missing a field the signature covers (key_id, publisher, issued_at, digest, value)", SCHEMA));
  if (Object.keys(sig).some((k) => k !== "version" && k !== "feed_sha384" && k !== "value")) return early("MALFORMED", feedFail("feed_unknown_member", "the signature block has a member this format does not allow", SCHEMA));
  const bad = unrepresentable(f);
  if (bad) return early("MALFORMED", feedFail("feed_value_unrepresentable", `the feed holds ${bad}; this checker refuses it rather than read it differently from another checker`, SCHEMA));

  const checks = [rec(SCHEMA, "PASS", [`${FEED_SCHEMA}, signature ${FEED_SIGNATURE_VERSION}; the file needs checker ${minimum}, this is ${VERIFIER_VERSION}`])];
  const finish = (outcome, sigCheck) => {
    checks.push(sigCheck);
    return { outcome, checks, info };
  };
  const SIG = "feed_signature";
  trustedKeys = await consolidateKeys(trustedKeys || []);
  const candidates = trustedKeys.filter((k) => k.signing_key_id === keyId);
  if (!candidates.length) return finish("UNKNOWN_ISSUER", feedFail("feed_issuer_unknown", `the file was signed with key ${pyRepr(keyId)}, which this checker does not pin. The file is not shown to be forged: this checker may be older than the key. Get the current checker from kanonik.ai/verify, or run again with --online.`));

  let digest;
  try {
    digest = await sha384Hex(canonicalBytes(f));
  } catch (e) {
    return finish("MALFORMED", feedFail("feed_unreadable", `the feed cannot be put in canonical form: ${e.message || e}`));
  }
  if (digest !== digestStated) return finish("BAD_SIGNATURE", feedFail("feed_changed", "the feed is not the one that was signed: its digest differs from the signed digest (changed after signing, or damaged)"));
  let signingInput, rawSig;
  try {
    signingInput = canonicalBytes({ version: FEED_SIGNATURE_VERSION, feed_sha384: digest, publisher_public_id: pubId, issued_at: issued, key_id: keyId });
    rawSig = derToRawEcdsa(strictRootB64(sig.value), 48);
  } catch {
    return finish("BAD_SIGNATURE", feedFail("feed_signature_unreadable", "the signature is empty or is not canonical base64"));
  }
  let matched = null;
  for (const k of candidates) {
    try {
      const key = await globalThis.crypto.subtle.importKey("spki", pemToDer(typeof k.pem === "string" ? k.pem : new TextDecoder().decode(k.pem)), { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
      if (await globalThis.crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, rawSig, signingInput)) {
        matched = k;
        break;
      }
    } catch { /* try the next pinned key with this id */ }
  }
  if (!matched) return finish("BAD_SIGNATURE", feedFail("feed_signature_invalid", `the signature does not verify under any pinned key with id ${pyRepr(keyId)}: signed by another key, or changed after signing`));
  if (matched.status === "revoked") return finish("KEY_REVOKED", feedFail("feed_key_revoked", `the key ${pyRepr(keyId)} that signed this file has been revoked by Kanonik. Do not rely on it.`));

  const notes = [];
  let status = "PASS";
  let outcome;
  const env = matched.env || "";
  if (matched.class === "sample") {
    status = "DEGRADED";
    notes.push(SAMPLE_KEY_NOTE);
    outcome = "VERIFIED_NON_PRODUCTION";
  } else if (env === "production") {
    outcome = "VERIFIED";
    notes.push(`ECDSA P-384 + SHA-384 signature verified against Kanonik's PINNED PRODUCTION key (id ${pyRepr(keyId)}); issued ${issued}`);
    if (matched.status === "retired") notes.push("that key is retired: it no longer signs, and a file it signed while active still verifies.");
  } else {
    status = "DEGRADED";
    outcome = "VERIFIED_NON_PRODUCTION";
    notes.push(`signature verified against a pinned NON-PRODUCTION Kanonik key (env=${env || "dev"}); the file is structurally sound but is NOT attestable to Kanonik's PRODUCTION key. Expected for integration/dev files.`);
  }
  notes.push("What this shows: Kanonik attested this is what the company's public trust page listed when it was issued, and it is unchanged since. It does not show any listed text is true, and it says nothing about the page now.");
  checks.push(rec(SIG, status, notes));

  const items = Array.isArray(f.items) ? f.items : [];
  let errs = feedShapeErrors(f);
  const issuedS = utcSeconds(issued);
  const validS = utcSeconds(f.valid_until);
  if (!errs.length && (issuedS === null || validS === null)) errs = ["feed: issued_at or valid_until is not a real time"];
  if (!errs.length && validS < issuedS) errs = ["feed: valid_until is before issued_at"];
  if (errs.length) {
    checks.push(rec("feed_shape", "FAIL", [], [{ kind: "feed_shape_invalid", message: `the signed feed does not match the format ${FEED_SCHEMA}: ${errs.join("; ")}` }], items.length));
    return { outcome: "MALFORMED", checks, info };
  }
  checks.push(rec("feed_shape", "PASS", [`${items.length} item(s), every member is one the format lists`], [], items.length));

  const nowS = now === undefined || now === null ? Date.now() / 1000 : now;
  const age = Math.max(0, Math.trunc(nowS - issuedS));
  Object.assign(info, {
    publisher: f.publisher.label, publisher_public_id: pubId, proved_domain: f.profile && f.profile.proved_domain, issued_at: issued, valid_until: f.valid_until, age_seconds: age,
    feed_url: f.feed_url, feed_sha384: digest, key_class: outcome === "VERIFIED" ? "production" : "non_production", items: feedItemRows(f),
  });
  if (nowS > validS) {
    checks.push(rec("feed_freshness", "FAIL", [], [{ kind: "feed_stale", message: feedStaleMessage(issued) }]));
    info.stale = true;
    return { outcome: "STALE", checks, info };
  }
  checks.push(rec("feed_freshness", "PASS", [`copy age ${ageWords(age)}; good until ${f.valid_until}`]));
  info.stale = false;
  return { outcome, checks, info };
}

export const feedSignatureHeld = (outcome) => outcome.startsWith("VERIFIED") || outcome === "STALE";

// Differences by item (public_id) between a copy and the live feed: added, removed, status changed, version changed.
export function diffFeedItems(oldRows, newRows) {
  const o = new Map(oldRows.map((r) => [r.public_id, r]));
  const n = new Map(newRows.map((r) => [r.public_id, r]));
  const sorted = (m) => [...m.keys()].sort();
  const out = { added: [], removed: [], status_changed: [], version_changed: [] };
  for (const pid of sorted(n)) if (!o.has(pid)) out.added.push({ public_id: pid, title: n.get(pid).title, record_status: n.get(pid).record_status });
  for (const pid of sorted(o)) {
    if (!n.has(pid)) {
      out.removed.push({ public_id: pid, title: o.get(pid).title, record_status: o.get(pid).record_status });
      continue;
    }
    for (const [key, bucket] of [["record_status", "status_changed"], ["version", "version_changed"]]) {
      if (o.get(pid)[key] !== n.get(pid)[key]) out[bucket].push({ public_id: pid, title: n.get(pid).title, from: o.get(pid)[key] ?? null, to: n.get(pid)[key] ?? null });
    }
  }
  return out;
}

// Where a signed manifest digest is listed in a feed: "" (not listed), "profile" or the item's public id.
export function feedListsManifest(feed, digest) {
  if (isObj(feed.profile) && feed.profile.manifest_sha384 === digest) return "profile";
  for (const it of Array.isArray(feed.items) ? feed.items : []) if (isObj(it) && it.manifest_sha384 === digest) return String(it.public_id);
  return "";
}

// verifyFeed takes the parsed feed file and returns the same summary shape verify.py --feed prints on stdout.
// opts: {trustedKeys (added to the shipped set), pinned (replaces it, for tests), now (epoch seconds), live:
// {state, doc} from fetchLiveFeed, disclosure (a parsed disclosure file), disclosureGiven}.
export async function verifyFeed(doc, opts = {}) {
  const trustedKeys = [];
  for (const k of opts.pinned || [...DEFAULT_TRUSTED_KEYS, ...(opts.trustedKeys || [])]) {
    const e = await keyEntry(k, keyStatus(k.status));
    if (e) trustedKeys.push(e);
  }
  const now = opts.now === undefined || opts.now === null ? Date.now() / 1000 : opts.now;
  const { outcome, checks, info } = await runFeedChecks(doc, trustedKeys, now);
  let online = { state: "not_requested" };
  let discl = { given: false };
  if (opts.live) {
    const on = rec("feed_online", "PASS", []);
    const state = opts.live.state;
    online = { state };
    if (state === "ok") {
      const l = await runFeedChecks(opts.live.doc, trustedKeys, now);
      online.live_outcome = l.outcome;
      online.live_info = l.info;
      if (!feedSignatureHeld(l.outcome)) {
        on.status = "DEGRADED";
        on.notes.push(`the live file did not check out (${l.outcome}), so no differences are listed. Do not rely on it.`);
      } else if (!feedSignatureHeld(outcome)) {
        on.status = "DEGRADED";
        on.notes.push("the copy's signature did not hold, so it is not compared with the live file.");
      } else {
        const d = diffFeedItems(info.items, l.info.items);
        online.diff = d;
        if (l.outcome === "STALE") {
          on.status = "DEGRADED";
          on.notes.push(`the live file is itself past its valid_until (${l.info.valid_until}); fetch it again later.`);
        }
        if (info.publisher_public_id !== l.info.publisher_public_id) {
          on.status = "DEGRADED";
          on.notes.push("the live file names a different publisher id than this copy.");
        }
        if (!Object.values(d).some((x) => x.length)) on.notes.push("the live feed lists the same items with the same status words as this copy.");
        else {
          on.status = "DEGRADED";
          for (const it of d.added) on.notes.push(`added since this copy: ${it.title} (${it.public_id})`);
          for (const it of d.removed) on.notes.push(`removed since this copy: ${it.title} (${it.public_id}). Stop showing it.`);
          for (const it of d.status_changed) on.notes.push(`status changed: ${it.title} (${it.public_id}): ${it.from} -> ${it.to}`);
          for (const it of d.version_changed) on.notes.push(`version changed: ${it.title} (${it.public_id}): ${it.from} -> ${it.to}`);
        }
      }
    } else if (state === "not_found") {
      on.status = "DEGRADED";
      on.notes.push(FEED_NOT_PUBLISHED);
    } else if (state === "refused") {
      on.status = "DEGRADED";
      on.notes.push("the feed address in this file is not https://share.kanonik.ai/t/{slug}/feed.json, so it was not fetched.");
    } else {
      on.status = "DEGRADED";
      on.notes.push("the live feed could not be read; nothing is compared. The result above is for the copy only.");
    }
    checks.push(on);
  }
  if (opts.disclosureGiven) {
    const dc = rec("feed_lists_disclosure", "PASS", []);
    const d = await runDisclosureChecks(opts.disclosure, await consolidateKeys(trustedKeys));
    discl = { given: true, outcome: d.outcome, listed: "" };
    if (!d.outcome.startsWith("VERIFIED")) {
      dc.status = "FAIL";
      dc.anomalies.push({ kind: "disclosure_not_confirmed", message: `the item file does not verify on its own (${d.outcome}), so it cannot be confirmed as listed in the feed` });
    } else if (!feedSignatureHeld(outcome)) {
      dc.status = "FAIL";
      dc.anomalies.push({ kind: "feed_not_confirmed", message: `the feed does not verify (${outcome}), so the item cannot be confirmed as listed in it` });
    } else {
      const dig = await sha384Hex(canonicalBytes(opts.disclosure.manifest));
      const where = feedListsManifest(doc.feed, dig);
      discl.manifest_sha384 = dig;
      discl.listed = where;
      if (where) dc.notes.push("the item's signed manifest digest is listed in the feed" + (where === "profile" ? " (the page profile)" : ` (item ${where})`));
      else {
        dc.status = "FAIL";
        dc.anomalies.push({ kind: "disclosure_not_in_feed", message: "this item's signed manifest digest is not listed in the feed. An on-request line lists no digest, by design; an open line that is missing was not published on this page." });
      }
    }
    checks.push(dc);
  }
  const byStatus = { PASS: 0, FAIL: 0, DEGRADED: 0 };
  for (const r of checks) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
  const overall = byStatus.FAIL > 0 ? "FAIL" : byStatus.DEGRADED > 0 ? "DEGRADED" : "PASS";
  return {
    schema_version: "v1",
    verifier_version: VERIFIER_VERSION,
    mode: "feed",
    outcome,
    // What the file says about itself is returned only when the signature held: otherwise it is unverified text.
    feed: feedSignatureHeld(outcome) ? info : {},
    online,
    disclosure: discl,
    overall_status: overall,
    summary: byStatus,
    checks,
  };
}

// verifyFeedText takes the file's text or bytes. A file over 1 MiB is refused before it is parsed.
// hasDuplicateKeys reports whether any object in a text that is already known to be valid JSON names a member twice. JSON.parse keeps
// the last one silently; a consumer whose parser keeps the first would read a different copy than the one the signature covers.
function hasDuplicateKeys(text) {
  let i = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const str = () => {
    let j = i + 1;
    while (j < text.length && text[j] !== '"') { if (text[j] === "\\") j++; j++; }
    const raw = text.slice(i, j + 1);
    i = j + 1;
    return JSON.parse(raw);
  };
  const val = () => {
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const seen = new Set();
      ws();
      if (text[i] === "}") { i++; return false; }
      for (;;) {
        ws();
        const k = str();
        if (seen.has(k)) return true;
        seen.add(k);
        ws();
        i++; // the colon
        if (val()) return true;
        ws();
        if (text[i] === ",") { i++; continue; }
        i++; // the closing brace
        return false;
      }
    }
    if (c === "[") {
      i++;
      ws();
      if (text[i] === "]") { i++; return false; }
      for (;;) {
        if (val()) return true;
        ws();
        if (text[i] === ",") { i++; continue; }
        i++; // the closing bracket
        return false;
      }
    }
    if (c === '"') { str(); return false; }
    while (i < text.length && !",]} \t\n\r".includes(text[i])) i++;
    return false;
  };
  return val();
}

export async function verifyFeedText(input, opts = {}) {
  const size = typeof opts.size === "number" ? opts.size : typeof input === "string" ? te.encode(input).length : input.byteLength;
  const refuse = (kind, message) => {
    const checks = [discFail("feed_schema_and_version", kind, message)];
    return { schema_version: "v1", verifier_version: VERIFIER_VERSION, mode: "feed", outcome: "MALFORMED", feed: {}, online: { state: "not_requested" }, disclosure: { given: false }, overall_status: "FAIL", summary: { PASS: 0, FAIL: 1, DEGRADED: 0 }, checks };
  };
  if (size > FEED_MAX_BYTES) return refuse("feed_too_large", `the file is larger than ${FEED_MAX_BYTES} bytes (1 MiB); this checker refuses it before reading it`);
  let doc;
  try {
    let text = typeof input === "string" ? input : new TextDecoder("utf-8", { fatal: true }).decode(input);
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1); // a byte-order mark is not part of the JSON
    doc = JSON.parse(text);
    if (hasDuplicateKeys(text)) throw new Error("duplicate key");
  } catch {
    return refuse("feed_malformed", "this is not a trust feed file: it is not JSON, or it names a member twice");
  }
  return verifyFeed(doc, opts);
}

// Exposed for the parity tests only (tests/run_mjs_keys.mjs); nothing in the page uses it.
export const __testing = { versionGreater, verifySigAgainstTrusted, derToRawEcdsa, chainRootSignedPayload, recordCheckpointSignedPayload, sealClaim, strictRootB64 };

// ── shared helpers ───────────────────────────────────────────────────────────

const seq = (e) => parseInt(e.sequence_number || 0, 10);

function decodePayload(ev) {
  const raw = ev.payload || "";
  if (!raw) return {};
  try {
    return JSON.parse(new TextDecoder().decode(b64ToBytes(raw)));
  } catch {
    return {};
  }
}

// Committed-event families and HOW each is Verifier-graded. Kept in lockstep
// with verify.py: a bundle that passes one verifier and fails the other is
// worse than either being wrong. Coverage is EXHAUSTIVE and FAIL-CLOSED - a
// `*.committed.v1` kind absent from every set below FAILs
// (committed_kind_unclassified).

// The verdict lives INSIDE the committed event as a required schema field; the
// model rejects one sealed without it, so an absent embedded verdict FAILs.
const COMMITTED_EMBEDDED_REQUIRED = new Set([
  "mapping.committed.v1",
  "link.committed.v1",
  "claim.committed.v1",
  "audit.finding.recorded.v1",
  // An operational fact carries its soundness verdict embedded (2.7.2).
  "operational_fact.committed.v1",
]);

// Always graded via a standalone verifier.verdict.v1 (checked before this pass,
// proven safe); an absent verdict is a real bypass -> FAIL. Their authoritative
// verdict is the standalone one; an embedded verdict must NOT stand in for it.
const COMMITTED_VERDICT_REQUIRED = new Set([
  "internal_control.committed.v1",
  "policy.committed.v1",
  "procedure.committed.v1",
]);

// Kinds whose schema gained the verdict field only later; an event sealed
// before it legitimately carries NO verdict and must still verify. Absent ->
// DEGRADE (not FAIL), so a legitimate full-chain export is not broken. They
// accept an embedded verdict when present; present-but-rejected still FAILs.
const COMMITTED_VERDICT_HISTORICAL_OPTIONAL = new Set([
  "asset.committed.v1",
  "risk.committed.v1",
  "vendor.committed.v1",
  "soa_decision.committed.v1",
  // An audit session embeds or pairs a verdict; sessions sealed before the
  // field existed carry none -> DEGRADE (2.7.4).
  "audit.session.created.v1",
]);

// No model verdict BY DESIGN - a grouping / envelope / rule-only seal whose
// graded content lives elsewhere. Requiring a verdict on the parent would
// force-fail every legitimate such bundle; its members carry the verdicts.
const COMMITTED_VERDICT_EXEMPT = new Set([
  // An answer set is rule-tier only; its graded content is the claims it cites.
  "questionnaire_response.committed.v1",
  // The generic external-write envelope; it materialises into the entity
  // `*.committed.v1` events, which carry the verdicts.
  "canonical.write.committed.v1",
  // The parent seal of a package: it GROUPS its members under one approval, it
  // never substitutes for them. Every member still emits its own Verifier
  // verdict + `*.committed.v1`; the unit seal itself carries none by design.
  "package_unit.committed.v1",
]);

const EMBEDDED_VERDICT = COMMITTED_EMBEDDED_REQUIRED;
const COMMITTED = new Set([
  ...COMMITTED_EMBEDDED_REQUIRED,
  ...COMMITTED_VERDICT_REQUIRED,
  ...COMMITTED_VERDICT_HISTORICAL_OPTIONAL,
  ...COMMITTED_VERDICT_EXEMPT,
]);

// Human-decision writes that are NOT *.committed.v1 events and carry NO model
// verdict BY DESIGN (2.7.4): the person is the decision, there is nothing to
// grade. Classified so the skip is counted, not silent. Kept apart from
// COMMITTED so the embedded-verdict replay checks do not walk them. Mirrors
// verify.py GATED_WRITE_VERDICT_EXEMPT.
const GATED_WRITE_VERDICT_EXEMPT = new Set([
  "evidence.captured.v1",
  "control_test.executed.v1",
  "risk.accepted.v1",
  "remediation.applied.v1",
  "exception.approved.v1",
  "disclosure.published.v1",
  "access_grant.approved.v1",
  "branding.recorded.v1",
  "nda_text.recorded.v1",
  "standing_summary.published.v1",
  "subprocessor_list.published.v1",
  "third_party_document.recorded.v1",
]);
// Trust page writes carry no model verdict, but one that does carry a verdict which did not pass is not an approved act.
const TRUST_PAGE_WRITE_EVENTS = new Set([
  "disclosure.published.v1", "access_grant.approved.v1", "branding.recorded.v1", "nda_text.recorded.v1",
  "standing_summary.published.v1", "subprocessor_list.published.v1", "third_party_document.recorded.v1",
]);
function trustWriteCarriesFailedVerdict(p) {
  const v = p.verifier_verdict;
  if (v === undefined || v === null) return false;
  if (typeof v !== "object" || Array.isArray(v)) return true;
  if (v.passed === true) return false;
  return !["PASSED", "APPROVED", "PASS"].includes(String(v.outcome == null ? "" : v.outcome).trim().toUpperCase());
}

// Carries its own grade (verdict_outcome, required APPROVED), so it is validated
// rather than exempt. Mirrors verify.py GATED_WRITE_OUTCOME_CHECKED.
const HUMAN_RECORD_REPLACEMENTS = new Set(["evidence.superseded.v1", "control_test.superseded.v1"]);
const GATED_WRITE_OUTCOME_CHECKED = new Set(["conformance.attested.v1"]);

// BEGIN GENERATED LIFECYCLE POLICY
const LIFECYCLE_VERDICT_POLICY = {
  "audit.finding.amended.v1": {
    "reason": "A replacement version carries its own grade; the grade of an earlier version does not count.",
    "stance": "embedded"
  },
  "audit.session.finalized.v1": {
    "reason": "A completeness check and a reference to the signed chain head; findings are graded on their own.",
    "stance": "exempt"
  },
  "audit.session.state_changed.v1": {
    "reason": "The audit session moved to a new state; nothing new in it needs a grade.",
    "stance": "exempt"
  },
  "claim.review_needed.v1": {
    "reason": "An automatic mark that a claim is out of date; no new claim is recorded.",
    "stance": "exempt"
  },
  "claim.superseded.v1": {
    "reason": "It points to a replacement record; the replacement is checked on its own.",
    "stance": "exempt"
  },
  "control_test.superseded.v1": {
    "reason": "A person replaced an evidence or test record, as when it was first captured; it needs no AI grade.",
    "stance": "exempt"
  },
  "evidence.superseded.v1": {
    "reason": "A person replaced an evidence or test record, as when it was first captured; it needs no AI grade.",
    "stance": "exempt"
  },
  "framework.licence.attested.v1": {
    "reason": "A person confirmed the licence; no AI judges licensing rights.",
    "stance": "exempt"
  },
  "lens.applicability.decided.v1": {
    "reason": "Checked by a fixed rule before it was recorded, so it needs no AI grade.",
    "stance": "rule"
  },
  "lens.applicability.superseded.v1": {
    "reason": "It points to a replacement record; the replacement is checked on its own.",
    "stance": "exempt"
  },
  "lens.decided.v1": {
    "reason": "Checked by a fixed rule before it was recorded, so it needs no AI grade.",
    "stance": "rule"
  },
  "lens.decision.superseded.v1": {
    "reason": "It points to a replacement record; the replacement is checked on its own.",
    "stance": "exempt"
  },
  "link.retracted.v1": {
    "reason": "A person withdrew a recorded link; it states nothing new, so it needs no AI grade.",
    "stance": "exempt"
  },
  "migration.summary.recorded.v1": {
    "reason": "Checked by a fixed rule before it was recorded, so it needs no AI grade.",
    "stance": "rule"
  },
  "migration.summary.superseded.v1": {
    "reason": "It points to a replacement record; the replacement is checked on its own.",
    "stance": "exempt"
  },
  "obligation.recorded.v1": {
    "reason": "Checked by a fixed rule before it was recorded, so it needs no AI grade.",
    "stance": "rule"
  },
  "policy_acknowledgement.recorded.v1": {
    "reason": "Checked by a fixed rule before it was recorded, so it needs no AI grade.",
    "stance": "rule"
  },
  "obligation.superseded.v1": {
    "reason": "It points to a replacement record; the replacement is checked on its own.",
    "stance": "exempt"
  },
  "package.created.v1": {
    "reason": "It only groups other records; each record in the group has its own grade.",
    "stance": "exempt"
  },
  "questionnaire_response.superseded.v1": {
    "reason": "It points to a replacement record; the replacement is checked on its own.",
    "stance": "exempt"
  },
  "soa_decision.revised.v1": {
    "reason": "A replacement version carries its own grade; the grade of an earlier version does not count.",
    "stance": "embedded"
  },
  "sod_exception.recorded.v1": {
    "reason": "It discloses an approval decision a person made; it is not a new record written by an AI.",
    "stance": "exempt"
  }
};
// END GENERATED LIFECYCLE POLICY

// An event carrying BOTH an approval token and an approver, of a kind this
// verifier does not classify. Mirrors verify.py _is_unclassified_gated_write.
function isUnclassifiedGatedWrite(et, p) {
  if (et.endsWith(".committed.v1") || et.startsWith("approval.")) return false;
  if (COMMITTED.has(et) || GATED_WRITE_VERDICT_EXEMPT.has(et) || GATED_WRITE_OUTCOME_CHECKED.has(et) || Object.hasOwn(LIFECYCLE_VERDICT_POLICY, et)) return false;
  return Boolean(p.approval_jti && p.approved_by_subject);
}

// ── the eight checks (mirror verify.py) ──────────────────────────────────────

// null for an entry served whole; "" for a well-formed withheld entry; else why it is malformed
// (mirror verify.py is_withheld_entry).
function withheldProblem(ev) {
  if (!ev.withheld) return null;
  if (ev.withheld !== "commercial") return `unknown withheld domain ${JSON.stringify(ev.withheld)}`;
  if (ev.event_type !== "withheld.v1") return "a withheld entry must carry the withheld.v1 type";
  // Strictly empty, spelled the same way in verify.py: absent, null or "".
  if (ev.payload !== undefined && ev.payload !== null && ev.payload !== "") return "a withheld entry must carry no payload";
  for (const f of ["schema_version", "entity_type", "entity_id", "idempotency_key", "caller_subject", "caller_session", "caller_tool"]) {
    if (ev[f] !== undefined && ev[f] !== null && ev[f] !== "") return `a withheld entry must carry no ${f}`;
  }
  try {
    const h = ev.event_hash || "";
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(h) || h.length % 4 !== 0 || atob(h).length !== 32) return "a withheld entry must keep a 32-byte event_hash";
  } catch (e) {
    return "a withheld entry must keep a 32-byte event_hash";
  }
  return "";
}

// Mirror verify.py check_withheld_positions: DEGRADED, never PASS, when positions are withheld.
function unsignedWithheldPositions(events) {
  const withheld = events.filter((e) => e.withheld);
  if (!withheld.length) return null;
  const domains = [...new Set(withheld.map((e) => String(e.withheld)))].sort();
  return {
    check: "withheld_positions",
    status: "DEGRADED",
    count: withheld.length,
    notes: [
      `${withheld.length} of ${events.length} positions are withheld (${domains.join(", ")}): their hashes and the links around them verify, but their content is outside this reader's grant and was not examined`,
      "the bundle does not yet carry a signed statement of which positions may be withheld; confirm the withheld count with the company",
    ],
    anomalies: [],
  };
}

// Signed withheld positions; kept separate from the chain/session checks.
async function checkWithheldPositions(events, statementBytes, root, trustedKeys) {
  if (statementBytes === undefined) return unsignedWithheldPositions(events);
  const withheld = events.filter(e => e.withheld);
  const r = { check: "withheld_positions", status: "PASS", count: withheld.length, notes: [], anomalies: [] };
  const exactKeys = (v, keys) => v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).sort().join(",") === keys.sort().join(",");
  const strictB64 = (s) => {
    if (typeof s !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4) throw new Error("invalid base64");
    return b64ToBytes(s);
  };
  try {
    const statement = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(statementBytes));
    if (!exactKeys(statement, ["payload", "signature"])) throw new Error("expected a payload and signature envelope");
    const payloadBytes = strictB64(statement.payload);
    const payloadText = new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes);
    const payload = JSON.parse(payloadText);
    if (!exactKeys(payload, ["version", "tenant_id", "chain_root_sha256", "signing_key_id", "positions"]) || canonicalMarshal(payload) !== payloadText) throw new Error("statement payload must use the canonical schema");
    if (payload.version !== "kanonik.withheld-positions.v1") throw new Error("unknown withheld statement signing domain");
    if (!root || !root.signature) throw new Error("statement requires a signed chain root");
    const rootBytes = chainRootSignedPayload(root);
    const rootHash = [...await sha256(rootBytes)].map(b => b.toString(16).padStart(2, "0")).join("");
    if (payload.chain_root_sha256 !== rootHash) throw new Error("statement belongs to a different chain root");
    if (payload.tenant_id !== root.tenant_id || payload.signing_key_id !== root.signing_key_id) throw new Error("statement tenant or key differs from the chain root");
    if (events.some(e => e.tenant_id !== payload.tenant_id)) throw new Error("event belongs to a different tenant");
    if (!Array.isArray(payload.positions) || !payload.positions.length || payload.positions.length !== withheld.length) throw new Error("statement must name exactly the withheld positions");
    const expected = new Map();
    for (const e of withheld) {
      const [state, seq] = canonicalInt(e.sequence_number);
      if (state !== "ok" || BigInt(seq) <= 0n || expected.has(seq) || withheldProblem(e) !== "") throw new Error("malformed or duplicate withheld event");
      expected.set(seq, e);
    }
    let previous = 0n;
    for (const position of payload.positions) {
      if (!exactKeys(position, ["sequence_number", "event_hash", "domain"])) throw new Error("malformed withheld position");
      const seq = position.sequence_number;
      if (typeof seq !== "string" || !/^[1-9][0-9]*$/.test(seq) || BigInt(seq) <= previous) throw new Error("positions must be unique and sorted positive decimal strings");
      previous = BigInt(seq);
      const e = expected.get(seq);
      if (!e || position.domain !== "commercial" || position.event_hash !== e.event_hash) throw new Error("statement does not match a withheld position");
    }
    const matched = await verifySigAgainstTrusted(derToRawEcdsa(strictB64(statement.signature), 48), payloadBytes, trustedKeys);
    if (!matched || !await verifySigAgainstTrusted(derToRawEcdsa(strictB64(root.signature), 48), rootBytes, [matched])) throw new Error("statement and root must be signed by the same pinned key");
    r.notes.push(`${withheld.length} commercial positions are signed as withheld by the chain-root key; their content is outside this reader's grant and was not examined`);
  } catch (e) {
    r.status = "FAIL";
    r.anomalies.push({ kind: "withheld_statement_invalid", message: String(e) });
  }
  return r;
}

async function checkHashChain(events, sessionDoc = null, trustedKeys = [], chainRoot = null, manifest = null) {
  if (sessionDoc !== null && sessionDoc !== undefined) return checkSessionPackIntegrity(events, sessionDoc, trustedKeys, chainRoot, manifest);
  const r = { check: "hash_chain_integrity", status: "PASS", count: 0, notes: [], anomalies: [] };
  if (!events.length) {
    r.status = "FAIL";
    r.anomalies.push({ kind: "empty_events", message: "events.jsonl carries no events" });
    return r;
  }
  const sorted = [...events].sort((a, b) => seq(a) - seq(b));
  r.count = sorted.length;
  let prior = null;
  let withheldCount = 0;
  for (let idx = 0; idx < sorted.length; idx++) {
    const ev = sorted[idx];
    let computed;
    const withheld = withheldProblem(ev);
    if (withheld !== null) {
      // Withheld entry: the stored event_hash is the leaf; only its exact shape is accepted.
      if (withheld) {
        r.status = "FAIL";
        r.anomalies.push({ kind: "withheld_entry_malformed", event_id: ev.event_id, message: withheld });
      } else {
        withheldCount++;
      }
      computed = ev.event_hash || "";
    } else {
      try {
        computed = bytesToB64(await computeEventHash(ev));
      } catch (e) {
        r.status = "FAIL";
        r.anomalies.push({ kind: "hash_compute_error", event_id: ev.event_id, message: String(e) });
        continue;
      }
    }
    if (computed !== (ev.event_hash || "")) {
      r.status = "FAIL";
      r.anomalies.push({ kind: "event_hash_mismatch", event_id: ev.event_id, message: "event_hash does not match recomputation; payload or header was modified" });
    }
    const storedPrev = ev.prev_hash || "";
    if (idx === 0) {
      const genesis = bytesToB64(new Uint8Array(32));
      if (storedPrev !== genesis) {
        r.status = "FAIL";
        r.anomalies.push({ kind: "genesis_prev_hash_mismatch", event_id: ev.event_id, message: "first event's prev_hash is not the genesis sentinel" });
      }
    } else if (storedPrev !== prior) {
      r.status = "FAIL";
      r.anomalies.push({ kind: "chain_link_broken", event_id: ev.event_id, message: "prev_hash does not match the prior event's event_hash; inserted, removed, or reordered" });
    }
    prior = ev.event_hash || "";
  }
  if (withheldCount) r.notes.push(`${withheldCount} events are withheld (outside the reader's grant): their stored hashes are accepted as leaves and every chain link around them is checked`);
  if (r.status === "PASS") r.notes.push(`verified ${sorted.length} events; all hashes + chain links match`);
  return r;
}

// Chain completeness, independent of the hash-linkage walk. Two witnesses that
// do not depend on recomputing the chain:
//   1. Sequence numbers are unique (a duplicate is a duplicated/injected
//      event). Every bundle.
//   2. For a v2 chain root only, chain_length (the signed TENANT event count)
//      equals the number of events walked - so an event omitted/truncated/
//      injected after signing is caught even when the remaining events still
//      form a valid hash chain. A v1/legacy root's chain_length is a GLOBAL
//      head sequence, not a count, so this witness is not applicable there
//      (documented limitation; never a FAIL - a pre-Amendment-2 bundle must
//      still verify). Sequence numbers are a shared global BIGSERIAL, so they
//      are unique but NOT contiguous 1..N for one tenant; contiguity is NOT
//      asserted. MUST stay identical to verify.py check_chain_completeness.
// The ONE integer wire grammar the completeness witness accepts - MUST stay
// identical to verify.py _is_decimal_int_string / _canonical_int. Python int()
// and JS Number() disagreed on non-canonical wire values (1.5, true, "1e0"),
// verdicting a malformed count/sequence differently across the two verifiers.
const SAFE_INT_MAX = Number.MAX_SAFE_INTEGER; // 2**53 - 1

function isDecimalIntString(s) {
  const body = s[0] === "-" ? s.slice(1) : s;
  if (body.length === 0) return false;
  for (const c of body) if (c < "0" || c > "9") return false; // ASCII digits only
  return true;
}

// Returns ["ok", canonicalDecimalStr] | ["unsafe", null] | ["bad", null].
// Mirror of verify.py _canonical_int.
function canonicalInt(raw) {
  if (typeof raw === "boolean") return ["bad", null];
  if (typeof raw === "number") {
    if (!Number.isInteger(raw)) return ["bad", null];
    if (!Number.isSafeInteger(raw)) return ["unsafe", null];
    return ["ok", String(raw)];
  }
  if (typeof raw === "string") {
    if (!isDecimalIntString(raw)) return ["bad", null];
    let big;
    try { big = BigInt(raw); } catch { return ["bad", null]; }
    if (big > BigInt(SAFE_INT_MAX) || big < -BigInt(SAFE_INT_MAX)) return ["unsafe", null];
    return ["ok", big.toString()];
  }
  return ["bad", null];
}

const SESSION_CHECKPOINTS_VERSION = "session-checkpoints.v1";

// Audit-session pack. Mirrors verify.py
// check_session_pack_integrity: per event, the hash recomputes and a signed
// record checkpoint attests it; gaps between events are expected.
async function checkSessionPackIntegrity(events, doc, trustedKeys, chainRoot = null, manifest = null) {
  const r = { check: "hash_chain_integrity", status: "PASS", count: 0, notes: [], anomalies: [] };
  const fail = (kind, message, extra = {}) => { r.status = "FAIL"; r.anomalies.push({ kind, message, ...extra }); };
  if (!events.length) { fail("empty_events", "events.jsonl carries no events; nothing to verify"); return r; }
  r.count = events.length;
  if (!doc || typeof doc !== "object" || Array.isArray(doc) || doc.version !== SESSION_CHECKPOINTS_VERSION || doc.scope !== "audit_session") {
    fail("session_checkpoints_malformed", `session_checkpoints.json is not a ${SESSION_CHECKPOINTS_VERSION} audit_session attestation`);
    return r;
  }
  const cpsRaw = doc.checkpoints === null || doc.checkpoints === undefined ? [] : doc.checkpoints;
  if (!Array.isArray(cpsRaw)) { fail("session_checkpoints_malformed", "session_checkpoints.json carries no checkpoints list"); return r; }
  const sessionId = String((manifest && manifest.session_id) || "");
  if (!sessionId || !events.some((e) => e.entity_type === "audit_session" && e.entity_id === sessionId)) {
    fail("session_pack_not_a_session", "session_checkpoints.json is present but the manifest names no audit session whose event is in events.jsonl; a full-chain export carries no such file");
  }
  const tenants = new Set(events.map((e) => String(e.tenant_id || "")));
  tenants.add(String(doc.tenant_id || ""));
  if (chainRoot && (chainRoot.signature || "")) tenants.add(String(chainRoot.tenant_id || chainRoot.TenantID || ""));
  if (tenants.size !== 1 || tenants.has("")) fail("session_tenant_mismatch", "the events, the checkpoints and the signed chain root do not all name the same workspace");
  const cps = new Map();
  for (const cp of cpsRaw) {
    const n = parseInt(cp && cp.sequence_number, 10);
    if (!Number.isInteger(n)) { fail("session_checkpoints_malformed", "a checkpoint carries no sequence number"); continue; }
    if (cps.has(n)) fail("session_checkpoint_duplicate", "two checkpoints name the same sequence number", { sequence_number: n });
    cps.set(n, cp);
  }
  let priorSeq = null;
  let priorHash = null;
  const seen = new Set();
  let linked = 0;
  let degraded = false;
  for (const ev of events) {
    const n = parseInt(ev.sequence_number, 10);
    if (!Number.isInteger(n)) { fail("sequence_number_unparseable", "event carries a non-integer sequence_number", { event_id: ev.event_id }); continue; }
    if (seen.has(n)) { fail("sequence_number_duplicate", "two events share a sequence_number", { sequence_number: n }); continue; }
    seen.add(n);
    if (priorSeq !== null && n < priorSeq) fail("session_events_out_of_order", "events.jsonl is not in ascending sequence order; an event was moved", { sequence_number: n, event_id: ev.event_id });
    const stored = ev.event_hash || "";
    const wp = withheldProblem(ev);
    if (wp) fail("withheld_entry_malformed", wp, { sequence_number: n, event_id: ev.event_id });
    if (wp === null) {
      let computed;
      try { computed = bytesToB64(await computeEventHash(ev)); } catch (e) {
        fail("hash_compute_error", `could not recompute hash: ${e}`, { sequence_number: n, event_id: ev.event_id });
        continue;
      }
      if (computed !== stored) fail("event_hash_mismatch", "event_hash does not match recomputation; event payload, header field, or hash was modified", { sequence_number: n, event_id: ev.event_id });
    }
    const cp = cps.get(n);
    cps.delete(n);
    if (!cp) {
      fail("session_event_unattested", "no signed checkpoint attests this event; it cannot be bound to the signed chain", { sequence_number: n, event_id: ev.event_id });
    } else {
      const sub = await checkRecordCheckpointSignature({ checkpoint: cp, event: ev }, trustedKeys);
      if (sub.status === "FAIL") {
        for (const a of sub.anomalies) fail("session_" + (a.kind || "checkpoint_failed"), a.message || "", { sequence_number: n, event_id: ev.event_id });
      } else if (sub.status === "DEGRADED") {
        degraded = true;
        for (const note of sub.notes) if (!r.notes.includes(note)) r.notes.push(note);
      }
    }
    if (priorHash !== null && (ev.prev_hash || "") === priorHash) linked++;
    priorSeq = priorSeq === null ? n : Math.max(priorSeq, n);
    priorHash = stored;
  }
  for (const n of [...cps.keys()].sort((a, b) => a - b)) fail("session_checkpoint_orphan", "a signed checkpoint names an event that is not in events.jsonl; an event was removed", { sequence_number: n });
  if (r.status === "PASS") {
    if (degraded) r.status = "DEGRADED";
    const gaps = Math.max(events.length - 1 - linked, 0);
    r.notes.push(`audit-session pack: verified ${events.length} events; every hash recomputes and every event is attested by a signed checkpoint. This is a selection of the workspace chain, so gaps between events are expected (${gaps} here) and are not a failure. The check does not show that no event was left out of, or added to, the selection`);
  }
  return r;
}

function checkChainCompleteness(events, chainRoot, sessionMode = false) {
  const r = { check: "chain_completeness", status: "PASS", count: 0, notes: [], anomalies: [] };
  const eventsSeen = events.length;
  r.count = eventsSeen;
  if (eventsSeen === 0) {
    r.status = "FAIL";
    r.anomalies.push({ kind: "empty_events", message: "events.jsonl carries no events; nothing to check for completeness" });
    return r;
  }
  // 1) Unique sequence numbers under the shared integer grammar.
  const seen = new Set();
  let unsafeSeq = 0;
  for (const ev of events) {
    const [state, canon] = canonicalInt(ev.sequence_number);
    if (state === "bad") {
      r.status = "FAIL";
      r.anomalies.push({ kind: "sequence_number_unparseable", event_id: ev.event_id, sequence_number: ev.sequence_number, message: "event carries a missing or non-canonical-integer sequence_number (booleans, fractions, and exponent strings are rejected); chain completeness cannot be established" });
      continue;
    }
    if (state === "unsafe") { unsafeSeq++; continue; }
    if (seen.has(canon)) {
      r.status = "FAIL";
      r.anomalies.push({ kind: "sequence_number_duplicate", sequence_number: canon, message: "two events share a sequence_number; an event was duplicated or injected" });
    }
    seen.add(canon);
  }
  if (unsafeSeq) {
    r.notes.push(`${unsafeSeq} sequence number(s) exceed the verifier's safe-integer range (2**53-1) and were excluded from the uniqueness witness; the hash-chain linkage check still bounds them.`);
  }
  // 2) Independent count witness, version-gated on the signed root.
  if (sessionMode) {
    if (chainRoot && TENANT_PURE_ROOT_VERSIONS.includes(String(chainRoot.version || chainRoot.Version || "v1"))) {
      const [st, cn] = canonicalInt("chain_length" in chainRoot ? chainRoot.chain_length : chainRoot.ChainLength);
      if (st === "ok" && eventsSeen > Number(cn)) {
        r.status = "FAIL";
        r.anomalies.push({ kind: "chain_length_exceeded", chain_length: Number(cn), events_seen: eventsSeen, message: "this selection holds more events than the signed workspace chain; events were injected" });
      }
    }
    r.notes.push("audit-session pack: the signed workspace chain length is not the number of events in this selection, so the count witness does not apply; every included event is attested by its own signed checkpoint");
  } else if (!chainRoot) {
    r.notes.push("no chain_root.json present; the independent count witness (chain_length == events walked) needs the signed root and was skipped - the hash-chain and chain-root-signature checks still bound completeness.");
  } else {
    const version = String(chainRoot.version || chainRoot.Version || "v1");
    let rawLen = "chain_length" in chainRoot ? chainRoot.chain_length : chainRoot.ChainLength;
    if (TENANT_PURE_ROOT_VERSIONS.includes(version)) {
      const [state, canon] = canonicalInt(rawLen);
      if (state === "bad") {
        r.status = "FAIL";
        r.anomalies.push({ kind: "chain_length_unparseable", chain_length: rawLen, message: "v2 chain_root.chain_length is missing or not a canonical integer (booleans, fractions, and exponent strings are rejected); the signed tenant event count cannot be verified" });
      } else if (state === "unsafe") {
        r.status = "FAIL";
        r.anomalies.push({ kind: "chain_length_unsafe_range", chain_length: rawLen, events_seen: eventsSeen, message: "v2 chain_root.chain_length exceeds the verifier's safe-integer range (2**53-1); a real tenant event count is small, so this value is corrupt or mislabeled" });
      } else {
        const chainLength = Number(canon);
        if (chainLength !== eventsSeen) {
          r.status = "FAIL";
          r.anomalies.push({ kind: "chain_length_mismatch", chain_length: chainLength, events_seen: eventsSeen, message: `the signed v2 chain root attests a tenant event count of ${chainLength} but events.jsonl carries ${eventsSeen}; events were omitted, truncated, or injected after signing` });
        } else {
          r.notes.push(`independent count witness: the signed v2 chain root's tenant event count (${chainLength}) matches the ${eventsSeen} events walked`);
        }
      }
    } else {
      r.notes.push("legacy v1 chain root: chain_length is a global head sequence, not the tenant event count, so the independent count witness is not applicable (documented limitation). v1 completeness rests on the hash-chain linkage and the chain-root head-hash signature checks.");
    }
  }
  if (r.status === "PASS" && r.anomalies.length === 0) {
    r.notes.push(`verified ${eventsSeen} events carry unique sequence numbers with no duplicated or injected entry`);
  }
  return r;
}

// A committed *.committed.v1 event only exists after the approval gate
// consumed a single-use token, so an approver subject / approval jti is proof
// a human decided. Mirrors verify.py _committed_has_approver.
// Truthy the way Python reads it (an empty list or object is empty), so py and js read an approver alike.
function pyTruthy(v) {
  if (Array.isArray(v)) return v.length > 0;
  if (v && typeof v === "object") return Object.keys(v).length > 0;
  return Boolean(v);
}
function committedHasApprover(p) {
  return pyTruthy(p.approved_by_subject) || pyTruthy(p.approved_by) || pyTruthy(p.approval_jti);
}

// A REJECTED verdict stands only with a SEPARATE approval.override.recorded.v1
// on the chain: it names the committed event by id, was appended after it,
// names the approver the committed event records, and has a non-blank reason.
// The inline override_acknowledged flag on the committed payload is the audited
// party's own assertion and is never read as proof. Mirrors verify.py
// _index_anchored_overrides + _committed_has_override.
const APPROVAL_OVERRIDE_EVENT_TYPE = "approval.override.recorded.v1";

function indexAnchoredOverrides(events) {
  const index = new Map();
  let firstSeq = null;
  for (const ev of events) {
    if (ev.event_type !== APPROVAL_OVERRIDE_EVENT_TYPE) continue;
    const s = seq(ev);
    if (firstSeq === null || s < firstSeq) firstSeq = s;
    const p = decodePayload(ev);
    const target = p.committed_event_id;
    if (typeof target === "string" && target) {
      if (!index.has(target)) index.set(target, []);
      index.get(target).push({ seq: s, p });
    }
  }
  return { index, firstSeq };
}

// Python's str.strip() whitespace set; JavaScript's trim() differs on some characters (U+0085, U+FEFF).
const PY_WHITESPACE = "\t\n\v\f\r\x1c\x1d\x1e\x1f \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000";
function pyStrip(s) {
  let i = 0, j = s.length;
  while (i < j && PY_WHITESPACE.includes(s[i])) i++;
  while (j > i && PY_WHITESPACE.includes(s[j - 1])) j--;
  return s.slice(i, j);
}
function committedApprover(p) {
  const a = pyTruthy(p.approved_by_subject) ? p.approved_by_subject : (pyTruthy(p.approved_by) ? p.approved_by : "");
  return typeof a === "string" ? pyStrip(a) : "";
}

// A committed event with no approver is never matched. Mirrors verify.py
// _committed_has_override.
function committedHasOverride(c, p, overrides) {
  const committedSeq = seq(c);
  const approver = committedApprover(p);
  if (!approver) return false;
  for (const { seq: s, p: ov } of overrides.index.get(String(c.event_id || "")) || []) {
    if (s <= committedSeq) continue;
    if (typeof ov.approver_subject !== "string" || ov.approver_subject !== approver) continue;
    if (typeof ov.reason !== "string" || !pyStrip(ov.reason)) continue;
    return true;
  }
  return false;
}

// A REJECTED record sealed before overrides were chain-anchored carries only
// the inline flag and reason. Not proof, so DEGRADED, never PASS; it counts as
// historical only when it states an override with a reason and an approver, no
// override event names it, and it sits before the chain's first override event
// (or the chain has none). Mirrors verify.py _historical_inline_override.
function historicalInlineOverride(c, p, overrides) {
  if (p.override_acknowledged !== true) return false;
  if (typeof p.override_reason !== "string" || !pyStrip(p.override_reason)) return false;
  if (!committedApprover(p)) return false;
  if ((overrides.index.get(String(c.event_id || "")) || []).length) return false;
  if (overrides.firstSeq !== null && seq(c) > overrides.firstSeq) return false;
  return true;
}

function rejectedOnly(outcomes) {
  return outcomes.length > 0 && outcomes.every((o) => String(o || "").trim().toUpperCase() === "REJECTED");
}

const HISTORICAL_OVERRIDE_MESSAGE =
  "this record was sealed over a rejected Verifier verdict and carries only an override flag and reason inside the record itself; no override event on the chain names it. It predates chain-anchored overrides, so it is reported DEGRADED: the override is not independently attestable, and the flag is not accepted as proof";

// Whether a Verifier outcome lets a committed record stand. APPROVED always;
// HUMAN_REVIEW iff a human approved through the gate (the human-in-the-loop
// happy path); REJECTED iff an admin acknowledged the override; anything else
// fails closed. Mirrors verify.py _outcome_satisfies.
function outcomeSatisfies(outcome, hasApprover, hasOverride) {
  const o = String(outcome || "").trim().toUpperCase();
  if (["APPROVED", "PASS", "PASSED"].includes(o)) return true;
  // NOT_ASSESSED seals on the ordinary click: like HUMAN_REVIEW, a recorded
  // human approver lets it stand.
  if (o === "HUMAN_REVIEW" || o === "NOT_ASSESSED") return hasApprover;
  if (o === "REJECTED") return hasOverride;
  return false;
}

// The outcome string of a standalone verifier.verdict.v1: the graded
// llm_tier_outcome, or a rule-tier verdict's passed bool mapped to
// APPROVED / REJECTED. Mirrors verify.py _standalone_verdict_outcome.
function standaloneOutcome(p) {
  if (p.llm_tier_outcome) return String(p.llm_tier_outcome);
  return p.passed === true ? "APPROVED" : "REJECTED";
}

// Classify the RAW verifier_verdict field, distinguishing an ABSENT optional
// field from a PRESENT-but-MALFORMED one. Must stay identical to verify.py's
// _verdict_field_state - a py/js disagreement here (falsy `{}` -> "absent" in
// one, truthy `{}` -> "malformed" in the other) was the parity break.
//   "absent"    - key missing or null.
//   "malformed" - present but not a non-empty plain object (empty object,
//                 array, scalar string, boolean, number) -> FAIL.
//   "present"   - a non-empty plain object -> validate its outcome.
function verdictFieldState(p) {
  if (!("verifier_verdict" in p) || p.verifier_verdict === null || p.verifier_verdict === undefined) return "absent";
  const v = p.verifier_verdict;
  if (typeof v === "object" && !Array.isArray(v) && Object.keys(v).length > 0) return "present";
  return "malformed";
}

// lifecycle contract; mirrors _check_lifecycle_verdicts.
/** An event type in words a person reads ("obligation.recorded.v1" -> "obligation recorded"), for the notes. */
function kindWords(et) {
  return String(et).replace(/\.v\d+$/, "").replace(/[._]+/g, " ")
    .replace("sod exception", "separation-of-duties exception").replace("soa decision", "statement of applicability decision");
}

function checkLifecycleVerdicts(events, r) {
  const rules = new Map();
  const overrides = indexAnchoredOverrides(events);
  const fail = (kind, e, message) => { r.status = "FAIL"; r.anomalies.push({kind, event_id: e.event_id, event_type: e.event_type, message}); };
  for (const e of events) {
    const et = e.event_type || "", p = decodePayload(e);
    if (et === "verifier.verdict.v1" && typeof p.related_proposal_id === "string" && p.related_proposal_id) {
      const list = rules.get(p.related_proposal_id) || [];
      list.push(p); rules.set(p.related_proposal_id, list);
    }
    if (GATED_WRITE_VERDICT_EXEMPT.has(et) || GATED_WRITE_OUTCOME_CHECKED.has(et) || HUMAN_RECORD_REPLACEMENTS.has(et)) {
      if (!committedApprover(p)) {
        fail("gated_write_without_approver", e, "a human-decision write must name its approver; a token id is not a person");
      }
    }
    if (!Object.hasOwn(LIFECYCLE_VERDICT_POLICY, et)) continue;
    const policy = LIFECYCLE_VERDICT_POLICY[et];
    r.notes.push(`${kindWords(et)}: ${policy.reason}`);
    if (verdictFieldState(p) === "malformed") {
      fail("lifecycle_malformed_verdict", e, "a supplied lifecycle verdict must be an object with an outcome"); continue;
    }
    const embedded = p.verifier_verdict;
    if (embedded && !outcomeSatisfies((embedded.outcome || (embedded.passed === true ? "APPROVED" : "")), Boolean(committedApprover(p)), committedHasOverride(e, p, overrides))) {
      fail("lifecycle_rejected_verdict", e, "the lifecycle write carries a non-approving verdict without an anchored override");
    }
    if (policy.stance === "embedded" && !embedded) fail("lifecycle_without_verdict", e, "replacement graded content requires its own embedded verdict");
    if (policy.stance === "rule") {
      const anchors = (rules.get(String(e.entity_id || "")) || []).filter(v => v.tier === "rule");
      if (!anchors.length || anchors[anchors.length-1].passed !== true) fail("lifecycle_without_rule_verdict", e, "the record requires a preceding passing rule verdict for its canonical id");
    }
  }
}

// 2.7.22: graded-content pairing. Mirrors verify.py _graded_content_outcomes. A record the AI
// re-proposed after the safety check's refinement loop is sealed with entity_id = the refinement id and
// payload.proposal_id = a batch member id, while the standalone verdict names the new draft's canonical id.
// The sealed commit_provenance.verifier carries the graded tuple, so the verdict is found by that content,
// for the always-graded kinds only.
const GRADED_CONTENT_PAIRING_KINDS = new Map([
  ["internal_control.committed.v1", "internal_control"],
  ["procedure.committed.v1", "procedure"],
  ["policy.committed.v1", "policy"],
]);
// Exact: no trimming, so py and js read an identifier the same way (their trims differ on some characters).
function gText(v) { return typeof v === "string" ? v : ""; }
function gEventSeq(e) {
  const [state, canon] = canonicalInt(e.sequence_number);
  return state === "ok" ? Number(canon) : null;
}
const GRADED_OUTCOME_WORD = /^[A-Za-z_]+$/;
// The outcome word of a verdict read by graded content. Only a plain ASCII word counts (anything else
// reads as no outcome, which never satisfies), so py and js cannot read it two ways.
function gradedOutcome(source, key) {
  const o = source[key];
  if (o !== undefined && o !== null && o !== "") return typeof o === "string" && GRADED_OUTCOME_WORD.test(o) ? o : "";
  return source.passed === true ? "APPROVED" : (key === "outcome" ? "" : "REJECTED");
}
function gradedContentOutcomes(c, p, verdictsByCih, proposedById, taken, anchors) {
  const kind = GRADED_CONTENT_PAIRING_KINDS.get(String(c.event_type));
  const prov = p.commit_provenance;
  if (!kind || !prov || typeof prov !== "object" || Array.isArray(prov)) return [[], false];
  const ver = prov.verifier;
  if (!ver || typeof ver !== "object" || Array.isArray(ver)) return [[], false];
  const lineage = gText(p.lineage_key);
  const cih = gText(ver.canonical_inputs_hash);
  const prompt = gText(ver.prompt_content_hash);
  const model = gText(ver.model);
  const rulePack = gText(ver.rule_pack_hash);
  const cseq = gEventSeq(c);
  if (!lineage || gText(prov.lineage_key) !== lineage || !cih || !prompt || !model || !rulePack || cseq === null) return [[], false];
  const outcomes = [];
  const used = [];
  for (const [vseq, vp] of verdictsByCih.get(cih) || []) {
    if (vseq >= cseq || gText(vp.prompt_hash) !== prompt) continue;
    if (gText(vp.related_entity_type) !== kind) continue;
    if (gText(vp.model_id) !== model || gText(vp.rule_pack_hash) !== rulePack) continue;
    const rpid = gText(vp.related_proposal_id);
    if (!rpid) continue;
    if (!(proposedById.get(rpid) || []).some(([pseq, ptype, plineage]) => ptype === `${kind}.proposed.v1` && pseq < vseq && plineage === lineage)) continue;
    const outcome = gradedOutcome(vp, "llm_tier_outcome");
    // A verdict one commit used, or one an id already pairs to a commit that needs a verdict, is
    // that commit's: it cannot serve this one. A verdict that does NOT support a write still counts
    // against it, whoever else used it, so it can never be hidden.
    const spent = taken.has(vseq) || (anchors.get(rpid) || []).some(([t]) => !COMMITTED_VERDICT_EXEMPT.has(t));
    if (spent && outcomeSatisfies(outcome, true, false)) continue;
    outcomes.push(outcome);
    if (!spent) used.push(vseq);
  }
  for (const u of used) taken.add(u);
  // own = at least one matching verdict was free for this commit. A spent rejection only counts against a write.
  return [outcomes, used.length > 0];
}

function checkVerdictPresence(events) {
  const r = { check: "verifier_verdict_presence", status: "PASS", count: 0, notes: [], anomalies: [] };
  checkLifecycleVerdicts(events, r);
  const verdicts = events.filter((e) => e.event_type === "verifier.verdict.v1");
  const committed = events.filter((e) => COMMITTED.has(e.event_type));
  // Fail-closed: a *.committed.v1 kind this verifier does not classify.
  const unclassified = events.filter(
    (e) => !COMMITTED.has(e.event_type) && String(e.event_type || "").endsWith(".committed.v1"),
  );
  let passed = 0;
  for (const v of verdicts) if (decodePayload(v).passed === true) passed++;
  r.count = verdicts.length;
  r.notes.push(`${verdicts.length} standalone verifier verdicts: ${passed} passed, ${verdicts.length - passed} rejected/non-passed`);

  for (const u of unclassified) {
    r.status = "FAIL";
    r.anomalies.push({ kind: "committed_kind_unclassified", event_id: u.event_id, event_type: u.event_type, message: "a committed event of a kind this verifier does not classify; its Verifier verdict cannot be located, so the write is unverifiable - the verifier must be taught this kind before the bundle is trusted" });
  }

  const gatedExempt = {};
  for (const e of events) {
    const et = String(e.event_type || "");
    if (GATED_WRITE_VERDICT_EXEMPT.has(et)) {
      gatedExempt[et] = (gatedExempt[et] || 0) + 1;
      if (TRUST_PAGE_WRITE_EVENTS.has(et) && trustWriteCarriesFailedVerdict(decodePayload(e))) {
        r.status = "FAIL";
        r.anomalies.push({ kind: "trust_write_verdict_not_passed", event_id: e.event_id, event_type: e.event_type, message: "a trust page write that carries a verifier verdict which did not pass; the write was refused by the rule check and cannot stand as an approved act" });
      }
    } else if (GATED_WRITE_OUTCOME_CHECKED.has(et)) {
      const outcome = decodePayload(e).verdict_outcome;
      if (String(outcome == null ? "" : outcome).trim().toUpperCase() !== "APPROVED") {
        r.status = "FAIL";
        r.anomalies.push({ kind: "attestation_verdict_not_approved", event_id: e.event_id, event_type: e.event_type, message: "an attestation whose carried verdict_outcome is missing or not APPROVED; the attested grade does not support the attestation" });
      }
    } else if (isUnclassifiedGatedWrite(et, decodePayload(e))) {
      r.status = "FAIL";
      r.anomalies.push({ kind: "gated_write_unclassified", event_id: e.event_id, event_type: e.event_type, message: "a write that carries an approval token and an approver, of a kind this verifier does not classify; whether it needed a Verifier verdict cannot be told, so the write is unverifiable - the verifier must be taught this kind before the bundle is trusted" });
    }
  }
  const gatedExemptKinds = Object.keys(gatedExempt).sort();
  if (gatedExemptKinds.length) {
    const total = gatedExemptKinds.reduce((n, k) => n + gatedExempt[k], 0);
    r.notes.push(`${total} human-decision writes carry no model verdict by design (the person is the decision; nothing to grade): ${gatedExemptKinds.map((k) => `${gatedExempt[k]} ${k}`).join(", ")}`);
  }

  if (!committed.length) {
    if (!unclassified.length) r.notes.push("no *.committed.v1 events in this bundle; nothing to pair");
    return r;
  }
  // Index verdicts by the proposal id they reference, carrying the OUTCOME
  // (not just passed) so a human_review verdict a human then approved is told
  // apart from a rejection. Mirrors verify.py _standalone_verdict_outcome.
  const idx = {};
  for (const v of verdicts) {
    const vp = decodePayload(v);
    const rpid = vp.related_proposal_id;
    if (rpid) (idx[String(rpid)] = idx[String(rpid)] || []).push(standaloneOutcome(vp));
  }
  // Indexes for the graded-content fallback (2.7.22).
  const verdictsByCih = new Map();
  for (const v of verdicts) {
    const vseq = gEventSeq(v);
    const vp = decodePayload(v);
    const vcih = gText(vp.canonical_inputs_hash);
    if (vseq !== null && vcih) {
      if (!verdictsByCih.has(vcih)) verdictsByCih.set(vcih, []);
      verdictsByCih.get(vcih).push([vseq, vp]);
    }
  }
  const proposedById = new Map();
  for (const e of events) {
    if (!String(e.event_type || "").endsWith(".proposed.v1")) continue;
    const pseq = gEventSeq(e);
    if (pseq === null) continue;
    const pp = decodePayload(e);
    for (const pid of new Set([gText(pp.canonical_id), gText(pp.proposal_id)])) {
      if (!pid) continue;
      if (!proposedById.has(pid)) proposedById.set(pid, []);
      proposedById.get(pid).push([pseq, String(e.event_type), gText(pp.lineage_key)]);
    }
  }
  const overrides = indexAnchoredOverrides(events);
  const degrade = (c, message, extra) => {
    // A kind that gained its verdict field only later carries none: legitimate
    // for a pre-field-era seal -> DEGRADE, never FAIL. A FAIL already set wins.
    if (r.status !== "FAIL") r.status = "DEGRADED";
    r.anomalies.push({ kind: "committed_without_verdict_historical", event_id: c.event_id, event_type: c.event_type, message, ...(extra || {}) });
  };
  let embeddedOk = 0;
  let standaloneOk = 0;
  let gradedOk = 0;
  const gradedTaken = new Set();
  const committedAnchors = new Map();
  // A verdict is also consumed by any other event that names its draft by entity_id (the lifecycle rule
  // verdicts), so those spend it too.
  for (const ev of events) {
    const et = String(ev.event_type);
    if (et === "verifier.verdict.v1" || et.endsWith(".proposed.v1") || COMMITTED.has(et) || COMMITTED_VERDICT_EXEMPT.has(et) || !ev.entity_id) continue;
    let key;
    try { key = String(ev.entity_id); } catch { continue; }
    if (!committedAnchors.has(key)) committedAnchors.set(key, []);
    committedAnchors.get(key).push([et, gEventSeq(ev)]);
  }
  for (const cc of committed) {
    const cp = decodePayload(cc);
    if (COMMITTED_VERDICT_EXEMPT.has(cc.event_type) || !cp || typeof cp !== "object" || Array.isArray(cp)) continue; // an exempt event cannot consume a verdict; only a mapping holds ids
    for (const a of [cp.proposal_id, cp.upstream_proposal_id, cc.entity_id]) {
      if (!a) continue; // every id the id pairing reads (it stringifies), so a verdict it consumed is spent
      let key;
      try { key = String(a); } catch { continue; } // an object whose toString throws pairs nothing
      if (!committedAnchors.has(key)) committedAnchors.set(key, []);
      committedAnchors.get(key).push([String(cc.event_type), gEventSeq(cc)]);
    }
  }
  // Claim graded-content verdicts in chain order for every commit, whichever way it is later accepted
  // (id pairing, embedded verdict or this fallback), so one verdict never serves two commits and the
  // outcome does not depend on the order of the file. Mirrors verify.py.
  const gradedByEvent = new Map();
  const claimOrder = committed.map((c, i) => [c, i]).sort((x, y) => {
    const a = gEventSeq(x[0]), b = gEventSeq(y[0]);
    if ((a === null) !== (b === null)) return a === null ? 1 : -1;
    return (a === null ? 0 : a - b) || x[1] - y[1];
  });
  for (const [c, i] of claimOrder) {
    const gp = decodePayload(c);
    if (GRADED_CONTENT_PAIRING_KINDS.has(c.event_type) && gp && typeof gp === "object" && !Array.isArray(gp)) gradedByEvent.set(i, gradedContentOutcomes(c, gp, verdictsByCih, proposedById, gradedTaken, committedAnchors));
  }
  for (const [ci, c] of committed.entries()) {
    const et = c.event_type;
    const p = decodePayload(c);

    // Rule-only / envelope kinds carry no model verdict by design.
    if (COMMITTED_VERDICT_EXEMPT.has(et)) continue;

    // A PRESENT-but-MALFORMED verdict is garbage, not an absent optional field:
    // FAIL on every non-exempt kind, BEFORE any bucket/standalone pairing, so a
    // historical-optional kind can never DEGRADE past it. Matches verify.py.
    if (verdictFieldState(p) === "malformed") {
      r.status = "FAIL";
      r.anomalies.push({ kind: "committed_with_malformed_embedded_verdict", event_id: c.event_id, event_type: et, message: "the committed event carries a verifier_verdict field that is not a valid verdict object (empty object, array, or scalar value); a malformed verdict is not an absent one - fail closed" });
      continue;
    }

    const hasApprover = committedHasApprover(p);
    const hasOverride = committedHasOverride(c, p, overrides);

    // Embedded-REQUIRED kinds carry the verdict INSIDE the committed event as a
    // required schema field; the model rejects one sealed without it. An
    // embedded verdict is no weaker: it sits in the same hash-chained, signed
    // event and cannot be separated from the thing it justifies.
    if (COMMITTED_EMBEDDED_REQUIRED.has(et)) {
      const ev = p.verifier_verdict;
      if (!ev || typeof ev !== "object") {
        r.status = "FAIL";
        r.anomalies.push({ kind: "committed_without_embedded_verdict", event_id: c.event_id, event_type: et, message: "this kind carries its Verifier verdict inside the committed event and the field is absent or malformed" });
        continue;
      }
      const outcome = ev.outcome ? String(ev.outcome) : (ev.passed === true ? "APPROVED" : "");
      if (!outcomeSatisfies(outcome, hasApprover, hasOverride)) {
        if (rejectedOnly([outcome]) && historicalInlineOverride(c, p, overrides)) {
          if (r.status !== "FAIL") r.status = "DEGRADED";
          r.anomalies.push({ kind: "committed_override_unanchored_historical", event_id: c.event_id, event_type: et, message: HISTORICAL_OVERRIDE_MESSAGE });
          continue;
        }
        r.status = "FAIL";
        r.anomalies.push({ kind: "committed_with_rejected_embedded_verdict", event_id: c.event_id, event_type: et, message: "the verdict embedded in this committed event does not record an approving outcome and no human approver or override recorded on the chain justifies the write" });
        continue;
      }
      embeddedOk++;
      continue;
    }

    // Historical-optional kinds may carry an embedded verdict (a later additive
    // anchor). Of the always-standalone kinds (internal_control / policy /
    // procedure) only a policy is also read from its own record (M-152).
    const historical = COMMITTED_VERDICT_HISTORICAL_OPTIONAL.has(et);
    // M-152: a policy is also read from its own record (kept in lockstep with
    // verify.py); controls and procedures still need the standalone verdict.
    let embedded = historical || et === "policy.committed.v1" ? p.verifier_verdict : null;
    if (embedded && typeof embedded === "object" && !historical) {
      // A policy's in-record verdict never hides a contradicting standalone one.
      const polOutcomes = [p.proposal_id, p.upstream_proposal_id, c.entity_id].filter(Boolean).map(String).flatMap((a) => idx[a] || []);
      if (polOutcomes.length && !polOutcomes.some((o) => outcomeSatisfies(o, hasApprover, hasOverride))) embedded = null;
      // A rejected verdict found by graded content (2.7.22) is never hidden by the in-record verdict:
      // every one allocated to this commit must support the write, else the commit fails here.
      const polGraded = embedded && typeof embedded === "object" ? (gradedByEvent.get(ci) || [[], false])[0] : [];
      if (polGraded.length && !polGraded.every((o) => outcomeSatisfies(o, hasApprover, hasOverride))) {
        const polFailing = polGraded.filter((o) => !outcomeSatisfies(o, hasApprover, hasOverride));
        const polEmbeddedOutcome = embedded.outcome ? String(embedded.outcome) : (embedded.passed === true ? "APPROVED" : "");
        if (rejectedOnly([...polFailing, polEmbeddedOutcome]) && historicalInlineOverride(c, p, overrides)) {
          if (r.status !== "FAIL") r.status = "DEGRADED";
          r.anomalies.push({ kind: "committed_override_unanchored_historical", event_id: c.event_id, event_type: et, message: HISTORICAL_OVERRIDE_MESSAGE });
          continue;
        }
        r.status = "FAIL";
        r.anomalies.push({ kind: "committed_with_rejected_verdict_only", event_id: c.event_id, event_type: et, outcomes: [...new Set(polGraded)].sort(), message: "a verdict graded on exactly what this commit sealed did not support the write, and no human approver or override recorded on the chain justifies it; the verdict inside the record does not hide it" });
        continue;
      }
    }
    if (embedded && typeof embedded === "object") {
      const outcome = embedded.outcome ? String(embedded.outcome) : (embedded.passed === true ? "APPROVED" : "");
      if (!outcomeSatisfies(outcome, hasApprover, hasOverride)) {
        if (rejectedOnly([outcome]) && historicalInlineOverride(c, p, overrides)) {
          if (r.status !== "FAIL") r.status = "DEGRADED";
          r.anomalies.push({ kind: "committed_override_unanchored_historical", event_id: c.event_id, event_type: et, message: HISTORICAL_OVERRIDE_MESSAGE });
          continue;
        }
        r.status = "FAIL";
        r.anomalies.push({ kind: "committed_with_rejected_embedded_verdict", event_id: c.event_id, event_type: et, message: "the verdict embedded in this committed event records a non-approving outcome and no human approver or override recorded on the chain justifies the write" });
        continue;
      }
      embeddedOk++;
      continue;
    }

    // No usable embedded verdict: pair a standalone verifier.verdict.v1 on any
    // id the record has worn (proposal_id / upstream_proposal_id / entity_id).
    const anchorIds = [p.proposal_id, p.upstream_proposal_id, c.entity_id].filter(Boolean).map(String);
    if (!anchorIds.length) {
      if (historical) {
        degrade(c, "carries no anchored Verifier verdict and no id to pair one. Provenance uncertain: this kind's verdict field is still schema-OPTIONAL, so this tool cannot determine whether this record predates the verdict field or is a policy-violating modern omission - reported DEGRADED, not failed, to avoid failing a legitimate historical export. The write is not independently attestable; strict failure of a modern omission requires the schema to make the field required");
      } else {
        r.status = "FAIL";
        r.anomalies.push({ kind: "committed_no_proposal_anchor", event_id: c.event_id, event_type: et, message: "committed event carries no proposal_id, upstream_proposal_id, or entity_id; cannot pair with a Verifier verdict - the write is unverifiable" });
      }
      continue;
    }
    let outcomes = anchorIds.flatMap((a) => idx[a] || []);
    // Only when the ids pair nothing: find the verdict by what was graded (2.7.22). Every verdict found
    // this way must support the write, so a rejected one is never hidden by an approved one.
    let graded = false;
    if (!outcomes.length && !historical) {
      const [gOutcomes, gOwn] = gradedByEvent.get(ci) || [[], false];
      outcomes = gOwn ? [...gOutcomes] : [];
      graded = outcomes.length > 0;
      const embG = p.verifier_verdict;
      if (graded && embG && typeof embG === "object") outcomes.push(gradedOutcome(embG, "outcome"));
    }
    if (!outcomes.length) {
      if (historical) {
        degrade(c, "carries no anchored Verifier verdict. Provenance uncertain: this kind's verdict field is still schema-OPTIONAL, so this tool cannot determine whether this record predates the verdict field or is a policy-violating modern omission - reported DEGRADED, not failed, to avoid failing a legitimate historical export. The write is not independently attestable; strict failure of a modern omission requires the schema to make the field required", { anchor_ids: anchorIds });
      } else {
        r.status = "FAIL";
        r.anomalies.push({ kind: "committed_without_verdict", event_id: c.event_id, event_type: et, anchor_ids: anchorIds, message: "no verifier.verdict.v1 references any id this committed event has worn" });
      }
      continue;
    }
    if (!(graded ? outcomes.every : outcomes.some).call(outcomes, (o) => outcomeSatisfies(o, hasApprover, hasOverride))) {
      if (rejectedOnly(outcomes) && historicalInlineOverride(c, p, overrides)) {
        if (r.status !== "FAIL") r.status = "DEGRADED";
        r.anomalies.push({ kind: "committed_override_unanchored_historical", event_id: c.event_id, event_type: et, proposal_id: anchorIds[0], message: HISTORICAL_OVERRIDE_MESSAGE });
        continue;
      }
      r.status = "FAIL";
      r.anomalies.push({ kind: "committed_with_rejected_verdict_only", event_id: c.event_id, event_type: et, outcomes: [...new Set(outcomes)], message: "the Verifier rejected this proposal and no human approver or override recorded on the chain justifies the write" });
      continue;
    }
    if (graded) { gradedOk++; continue; }
    standaloneOk++;
  }
  if (embeddedOk || standaloneOk) r.notes.push(`${embeddedOk} committed events carried an approving verdict EMBEDDED in the event; ${standaloneOk} paired an approving standalone verifier.verdict.v1`);
  if (gradedOk) r.notes.push(`${gradedOk} committed event${gradedOk === 1 ? "" : "s"} paired to ${gradedOk === 1 ? "its" : "their"} verifier verdict by graded content: the record was refined after grading, so its ids no longer meet the verdict's, and the verdict was matched on the inputs, prompt, model and rule pack the sealed commit records and on the record's lineage`);
  const unanchored = r.anomalies.filter((a) => a.kind === "committed_override_unanchored_historical").length;
  if (unanchored) r.notes.push(`LIMITATION: ${unanchored} record${unanchored === 1 ? "" : "s"} sealed over a rejected Verifier verdict carry only an override flag inside the record and no override event on the chain (sealed before overrides were chain-anchored); reported DEGRADED, not accepted as proof.`);
  const historicalAbsent = r.anomalies.filter((a) => a.kind === "committed_without_verdict_historical").length;
  if (historicalAbsent) r.notes.push(`LIMITATION (provenance uncertain): ${historicalAbsent} committed events of kinds whose verdict field is still schema-OPTIONAL carry no anchored verdict. This tool cannot determine whether they predate the verdict field or are policy-violating modern omissions, because the schema permits a verdict-less write; reported DEGRADED (not failed) so legitimate historical exports still verify. Strict failure of a modern omission requires the schema to make the field required.`);
  return r;
}

// A self-approval is a DISCLOSED, valid state (not a breach) when a matching
// sod_exception.recorded.v1 discloses the documented sole-admin exception
// (kind sole_admin_self_approval, exactly one active tenant-admin, same
// self-approving subject). The product allows this for single-admin (e.g.
// Solo-tier) tenants; the offline verifier must honour it or every Solo-tier
// bundle FAILs the "verify it yourself" tool.
function validSoleAdminException(exc, proposer, approver) {
  if (!exc) return false;
  if (exc.kind !== "sole_admin_self_approval") return false;
  if (exc.active_tenant_admin_count !== 1) return false;
  if ((exc.proposer_subject || "") !== proposer) return false;
  if ((exc.approver_subject || "") !== approver) return false;
  return true;
}

// The subjects holding an active tenant-admin role as of an approval: replay
// actor.role_assigned / role_revoked / person_departed events with a chain
// sequence BELOW the approval's. Mirrors verify.py _active_admins_at.
const ADMIN_ROLE_NAME = "tenant-admin";
// Timestamps compare at microsecond precision, as verify.py does: whole seconds
// from Date.parse, plus the first six fractional digits, as one BigInt.
// Date.parse alone drops everything below a millisecond.
const TS_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/;
function parseTs(raw) {
  if (typeof raw !== "string") return null;
  const m = TS_RE.exec(raw.trim());
  if (!m) return null;
  const secMs = Date.parse(m[1] + (m[3] === "Z" ? "Z" : m[3]));
  if (Number.isNaN(secMs)) return null;
  const micros = BigInt((m[2] || "").padEnd(6, "0").slice(0, 6));
  return BigInt(secMs) * 1000n + micros;
}
// approvalTime is a parseTs value, or null when the approval carries no readable
// time (then only the sequence order applies). Mirrors verify.py _active_admins_at.
function activeAdminsAt(roleEvents, approvalSeq, approvalTime) {
  // key -> { sub, role, intervals: [{ start, until }] }. A later grant adds an
  // interval, never replaces an active one; a revocation or departure only
  // ever shortens an interval.
  const held = new Map();
  const key = (sub, role) => sub + "\u0000" + role;
  const ENDED = -(2n ** 80n);
  const shorten = (intervals, at) => {
    for (const iv of intervals) iv.until = iv.until === null || at < iv.until ? at : iv.until;
  };
  const sorted = [...roleEvents].sort((a, b) => a.seq - b.seq);
  for (const { seq: s, et, p } of sorted) {
    if (s >= approvalSeq) break;
    const sub = p.person_oidc_sub;
    if (typeof sub !== "string" || !sub) continue;
    if (et === "actor.role_assigned.v1") {
      if (typeof p.role_name === "string" && p.role_name) {
        const k = key(sub, p.role_name);
        if (!held.has(k)) held.set(k, { sub, role: p.role_name, intervals: [] });
        const h = held.get(k);
        const start = parseTs(p.effective_from);
        h.intervals = h.intervals.filter((iv) => iv.start !== start);
        h.intervals.push({ start, until: parseTs(p.effective_until) });
      }
    } else if (et === "actor.role_revoked.v1") {
      const h = held.get(key(sub, String(p.role_name || "")));
      if (h) { const u = parseTs(p.effective_until); shorten(h.intervals, u === null ? ENDED : u); }
    } else if (et === "actor.person_departed.v1") {
      // A recorded departure ends every role held so far at once, whatever
      // departed_at says (the membership counter excludes the member).
      for (const h of held.values()) if (h.sub === sub) shorten(h.intervals, ENDED);
    }
  }
  const admins = new Set();
  for (const h of held.values()) {
    if (h.role !== ADMIN_ROLE_NAME) continue;
    for (const iv of h.intervals) {
      if (approvalTime !== null) {
        if (iv.start !== null && iv.start > approvalTime) continue;
        if (iv.until !== null && iv.until <= approvalTime) continue;
      } else if (iv.until === ENDED) continue;
      admins.add(h.sub);
      break;
    }
  }
  return admins;
}

// Record-kind self-seal. Mirrors verify.py (_author_self_seal_set_at +
// _record_kind_self_seal_ok). A tenant with a second eligible reviewer may
// still let ONE person accept AND seal a routine record with a single click and
// no separate exception event; the verifier confirms it against the CHAIN, not
// a claim on the approval.
const AUTHOR_SELF_SEAL_POLICY_KEY = "sod.author_self_seal_entity_types";
const TENANT_POLICY_SET_EVENT_TYPE = "tenant_policy.set.v1";
const DECISION_BASIS_AUTHOR_SELF_SEAL_RECORD_KIND = "author_self_seal_record_kind";
// CATALOGUE_DEFAULT_AUTHOR_SELF_SEAL mirrors packages/tenantpolicy/catalogue.yaml
// key sod.author_self_seal_entity_types `default`.
const CATALOGUE_V1_AUTHOR_SELF_SEAL = new Set([
  "evidence", "control_test", "audit_finding", "audit_session",
  "asset", "vendor", "mapping", "link",
  "claim", "questionnaire_response",
  "obligation", "lens_decision", "lens_applicability",
  "policy_acknowledgement",
  "migration_summary",
  "risk", "remediation",
]);
// Trust page (sod catalogue version 2). page_disclosure is not here: the public page keeps a second person.
const TRUST_PAGE_SELF_SEAL_KINDS = ["disclosure", "access_grant", "branding", "nda_text", "third_party_document"];
const CATALOGUE_DEFAULT_AUTHOR_SELF_SEAL = new Set([...CATALOGUE_V1_AUTHOR_SELF_SEAL, ...TRUST_PAGE_SELF_SEAL_KINDS]); // version 2 (newest)
// Newest version of the default (verify.py SOD_CATALOGUE_VERSION). Version 1 is everything through 2.7.15. An approval
// declares its version on its members (sod_catalogue_version); one that says nothing is read under version 1.
const SOD_CATALOGUE_VERSION = 2;
// The second-person floor (verify.py SECOND_PERSON_FLOOR_KINDS): no tenant set can hold these.
const SECOND_PERSON_FLOOR_KINDS = new Set(["policy", "soa_decision", "risk_acceptance", "page_disclosure"]);
function withoutFloor(set) { return new Set([...set].filter((k) => !SECOND_PERSON_FLOOR_KINDS.has(k))); }
const CATALOGUE_V1_RESOLVED = withoutFloor(CATALOGUE_V1_AUTHOR_SELF_SEAL);
const CATALOGUE_V2_RESOLVED = withoutFloor(CATALOGUE_DEFAULT_AUTHOR_SELF_SEAL);
function catalogueDefaultFor(payload) {
  let version = 1;
  for (const m of (payload && Array.isArray(payload.members) ? payload.members : [])) {
    if (m && typeof m === "object" && Number.isInteger(m.sod_catalogue_version) && m.sod_catalogue_version >= 2) version = 2;
  }
  return version >= 2 ? CATALOGUE_V2_RESOLVED : CATALOGUE_V1_RESOLVED;
}

// authorSelfSealSetAt resolves the author-may-self-seal kind set in force for
// an approval: the value from the LATEST tenant_policy.set.v1 for the key with
// seq < the approval's seq, else the embedded catalogue default.
function authorSelfSealSetAt(policySets, approvalSeq, payload) {
  let best = null;
  for (const ps of policySets) {
    if (ps.seq >= approvalSeq) continue;
    if (best === null || ps.seq > best.seq) best = ps;
  }
  if (best === null) return catalogueDefaultFor(payload);
  const out = new Set();
  for (const k of best.value || []) {
    const kind = String(k).trim().toLowerCase();
    if (kind && !SECOND_PERSON_FLOOR_KINDS.has(kind)) out.add(kind);
  }
  return out;
}

// recordKindSelfSealOk reports whether a proposer==approver approval is a valid
// record-kind self-seal: members[] present + non-empty, EVERY member's
// decision_basis is author_self_seal_record_kind, EVERY entity_kind in the
// resolved set. Returns { ok, reason }.
function recordKindSelfSealOk(payload, resolvedSet) {
  const members = payload.members;
  if (!Array.isArray(members) || members.length === 0) {
    return { ok: false, reason: "no members[] disclosure on the approval event" };
  }
  const offending = [];
  for (const m of members) {
    if (!m || typeof m !== "object") return { ok: false, reason: "malformed member entry" };
    if (m.decision_basis !== DECISION_BASIS_AUTHOR_SELF_SEAL_RECORD_KIND) {
      return { ok: false, reason: `a member's decision_basis is ${JSON.stringify(m.decision_basis)}, not "${DECISION_BASIS_AUTHOR_SELF_SEAL_RECORD_KIND}"` };
    }
    const kind = String(m.entity_kind || "").trim().toLowerCase();
    if (!kind) return { ok: false, reason: "a member has no entity_kind" };
    if (!resolvedSet.has(kind)) offending.push(kind);
  }
  if (offending.length) {
    return { ok: false, reason: "entity kind(s) " + [...new Set(offending)].sort().join(", ") + " are not in the author-may-self-seal set for this tenant" };
  }
  return { ok: true, reason: "" };
}

// canonJson is JSON with object keys sorted at every depth, matching verify.py.
function canonJson(v) {
  if (Array.isArray(v)) return "[" + v.map(canonJson).join(",") + "]";
  if (v && typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonJson(v[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}

// idKey is the tally key for an approval id. A string and a malformed id never
// share a key ("s:" vs "j:"), so the number 1 and the string "1" stay two ids;
// a malformed id is keyed by canonical JSON, so it is counted once and never throws.
function idKey(jti) {
  return typeof jti === "string" ? "s:" + jti : "j:" + canonJson(jti);
}

export function checkSoD(events) {
  const r = { check: "sod_separation_of_duties", status: "PASS", count: 0, notes: [], anomalies: [] };
  const issued = {};
  // approved keeps each payload with its chain seq, needed to resolve the
  // author-may-self-seal set in force at that point.
  const approved = [];
  const sodExceptions = {};
  // policySets collects tenant_policy.set.v1 for the author-self-seal key.
  const policySets = [];
  // roleEvents feeds the active-admin recompute for the sole-admin exception.
  const roleEvents = [];
  const unverifiableCountJtis = [];
  let dualControlled = 0;
  let disclosed = 0;
  const disclosedJtis = [];
  let recordSelfSeal = 0;
  const recordSelfSealJtis = [];
  const disclosedKeys = new Set(), recordSelfSealKeys = new Set();
  // Sets of approval ids, so every figure in the summary line has one
  // denominator: distinct approval ids.
  const rejectedIds = new Set(), expiredIds = new Set();
  // A batch approval is issued by approval.batch.issued.v1: counted in the
  // note, kept apart from `issued` so the proposer fallback is unchanged.
  const batchIssued = new Set();
  const issuedIdKeys = new Set();
  for (const ev of events) {
    const p = decodePayload(ev);
    if (["actor.role_assigned.v1", "actor.role_revoked.v1", "actor.person_departed.v1"].includes(ev.event_type)) {
      roleEvents.push({ seq: seq(ev), et: ev.event_type, p });
      continue;
    }
    if (ev.event_type === TENANT_POLICY_SET_EVENT_TYPE) {
      if (p.policy_key === AUTHOR_SELF_SEAL_POLICY_KEY) {
        policySets.push({ seq: seq(ev), value: p.policy_value, event_id: ev.event_id });
      }
      continue;
    }
    const jti = p.approval_jti;
    if (!jti) continue;
    if (ev.event_type === "approval.issued.v1") { issuedIdKeys.add(idKey(jti)); issued[jti] = p; }
    else if (ev.event_type === "approval.batch.issued.v1") batchIssued.add(jti);
    else if (ev.event_type === "approval.approved.v1") approved.push({ p, seq: seq(ev), time: parseTs(p.approved_at) ?? parseTs(ev.valid_time) });
    else if (ev.event_type === "sod_exception.recorded.v1") sodExceptions[jti] = p;
    else if (ev.event_type === "approval.rejected.v1" || ev.event_type === "approval.member.rejected.v1") rejectedIds.add(idKey(jti)); // a member rejection counts as a rejection of that approval id
    else if (ev.event_type === "approval.expired.v1") expiredIds.add(idKey(jti));
  }
  r.count = approved.length;
  const issuedIds = new Set([...issuedIdKeys, ...[...batchIssued].map(idKey)]);
  const approvedIds = new Set(approved.map(({ p: a }) => idKey(a.approval_jti)));
  const issuedCount = issuedIds.size;
  // The four tallies are different outcomes over distinct approval ids, not a
  // breakdown of the issued figure: an approval can carry several
  // events, and an id can appear with no issuance event in this bundle.
  r.notes.push(
    "Counted by approval id, each id once per outcome: " +
    `${issuedCount} approval${issuedCount === 1 ? "" : "s"} issued, ` +
    `${approvedIds.size} approved, ${rejectedIds.size} rejected, ${expiredIds.size} expired. ` +
    "These are separate tallies, not parts of one total.");
  if (approved.length !== approvedIds.size) {
    r.notes.push(`${approved.length} approved events were recorded for ${approvedIds.size} approval id${approvedIds.size === 1 ? "" : "s"}.`);
  }
  const approvedUnissued = [...approvedIds].filter((j) => !issuedIds.has(j)).length;
  if (approvedUnissued) {
    r.notes.push(
      `FINDING: ${approvedUnissued} of the ${approvedIds.size} approved ` +
      `id${approvedIds.size === 1 ? "" : "s"} ${approvedUnissued === 1 ? "has" : "have"} no issuance event in ` +
      "this bundle (neither approval.issued.v1 nor approval.batch.issued.v1), so who issued " +
      `${approvedUnissued === 1 ? "it" : "them"} and when is not ` +
      "shown here. Each is still checked below from its own approved event.");
  }
  const expiredUnissued = [...expiredIds].filter((j) => !issuedIds.has(j)).length;
  if (expiredUnissued) {
    r.notes.push(
      expiredUnissued === 1
        ? `FINDING: ${expiredUnissued} of the ${expiredIds.size} expired id${expiredIds.size === 1 ? "" : "s"} has no issuance event in this bundle.`
        : `FINDING: ${expiredUnissued} of the ${expiredIds.size} expired ids have no issuance event in this bundle.`);
  }
  for (const { p: a, seq: approvalSeq, time: approvalTime } of approved) {
    let proposer = a.proposer_subject || "";
    const approver = a.approved_by_subject || "";
    if (!proposer) proposer = (issued[a.approval_jti] || {}).proposer_subject || "";
    if (!proposer || !approver) {
      r.anomalies.push({ kind: "sod_subject_missing", approval_jti: a.approval_jti, message: "cannot perform SoD check (missing subject)" });
      continue;
    }
    if (proposer !== approver) dualControlled++;
    if (proposer === approver) {
      const exc = sodExceptions[a.approval_jti];
      let soleAdminOk = validSoleAdminException(exc, proposer, approver);
      if (soleAdminOk && roleEvents.some((e) => e.et === "actor.role_assigned.v1")) {
        // Recompute who was admin at this approval from the chain's own role
        // events; the exception's stated count is not trusted.
        const admins = activeAdminsAt(roleEvents, approvalSeq, approvalTime);
        soleAdminOk = admins.size === 1 && admins.has(approver);
      } else if (soleAdminOk) {
        // No role events in the bundle: the stated count cannot be checked.
        unverifiableCountJtis.push(String(a.approval_jti));
        continue;
      }
      if (soleAdminOk) {
        // Disclosed sole-admin self-approval: valid, not a breach.
        // Counted, not narrated. This used to push one note PER approval,
        // which on a real estate rendered hundreds of identical sentences
        // that differed only by an id and told the reader nothing the
        // summary below does not. The summary carries the count, the
        // meaning, and a sample of the ids; verify.py prints all of them.
        // distinct approval ids, not events
        if (!disclosedKeys.has(idKey(a.approval_jti))) {
          disclosedKeys.add(idKey(a.approval_jti));
          disclosed++;
          disclosedJtis.push(a.approval_jti);
        }
        continue;
      }
      // Record-kind self-seal: valid when every member is an
      // author-self-sealable record kind resolved from the chain.
      const resolvedSet = authorSelfSealSetAt(policySets, approvalSeq, a);
      const { ok, reason } = recordKindSelfSealOk(a, resolvedSet);
      if (ok) {
        if (!recordSelfSealKeys.has(idKey(a.approval_jti))) {
          recordSelfSealKeys.add(idKey(a.approval_jti));
          recordSelfSeal++;
          recordSelfSealJtis.push(a.approval_jti);
        }
        continue;
      }
      r.status = "FAIL";
      r.anomalies.push({ kind: "self_approval", approval_jti: a.approval_jti, message: "proposer and approver are the same OIDC subject with no disclosed sole-admin exception and no valid record-kind self-seal (" + reason + "); separation-of-duties breached" });
    }
  }
  if (recordSelfSeal) {
    const shown = recordSelfSealJtis.slice(0, SAMPLE_LIMIT);
    let note = recordSelfSeal + " self-approval" + (recordSelfSeal===1?"":"s") +
      " validated as a record-kind self-seal: the author accepted AND sealed a " +
      "routine record kind (for example evidence, a control test, or a mapping) " +
      "that this tenant's author-may-self-seal policy, resolved from the chain, " +
      "lets one person seal, so no second reviewer was required and no exception " +
      "event was needed.";
    if (shown.length) {
      note += " Approvals: " + shown.join(", ");
      if (recordSelfSealJtis.length > shown.length) {
        note += " and " + (recordSelfSealJtis.length - shown.length) +
          " more (run python3 chain/verify.py . for the complete list).";
      }
    }
    r.notes.push(note);
  }
  if (disclosed) {
    const shown = disclosedJtis.slice(0, SAMPLE_LIMIT);
    let note = disclosed + " self-approval" + (disclosed===1?"":"s") +
      " validated by a disclosed sole-admin exception recorded on this chain " +
      "(sod_exception.recorded.v1): the tenant's role events show exactly one " +
      "active administrator at the time, so proposer and approver are " +
      "necessarily the same person, and the exception says so on the record.";
    if (shown.length) {
      note += " Approvals: " + shown.join(", ");
      if (disclosedJtis.length > shown.length) {
        note += " and " + (disclosedJtis.length - shown.length) +
          " more (run python3 chain/verify.py . for the complete list).";
      }
    }
    r.notes.push(note);
  }
  if (unverifiableCountJtis.length) {
    if (r.status !== "FAIL") r.status = "DEGRADED";
    const n = unverifiableCountJtis.length;
    r.anomalies.push({ kind: "sole_admin_count_unverifiable", approval_jtis: unverifiableCountJtis, message: n + " sole-admin exception" + (n === 1 ? "" : "s") + " could not be checked: this bundle carries no actor.role_assigned.v1 events, so the number of active administrators cannot be recomputed. The exception's own stated count is not accepted as proof." });
  }
  r.details = { author_sealed_under_policy: recordSelfSeal, sole_admin_exceptions: disclosed, dual_controlled: dualControlled };
  r.notes.push("Approvals by who made them: " + recordSelfSeal + " author-sealed under policy; " + disclosed + " sole-admin self-approval" + (disclosed === 1 ? "" : "s") + "; " + dualControlled + " dual-controlled (a second person approved).");
  return r;
}

// Two-act oversight. Mirrors verify.py check_two_act. Some tenants keep two
// people on their governance documents: one drafts (with their AI) and accepts,
// a second person seals. approval.accepted.v1 records the acceptance and lists
// each member's decision (`accepted` = a governance record parked for a second
// person; `sealed` = a routine record the author sealed there and then).
// approval.approved.v1 (emitted when the second person seals) names the sealer
// and lists the same member proposal ids. This check confirms every GOVERNANCE
// record the author only accepted was sealed by a DIFFERENT subject. A record
// kind sealed with one click needs no second person. An accepted record with no
// seal yet is awaiting confirmation, not an anomaly.
const TWO_ACT_ACCEPTED_EVENT_TYPE = "approval.accepted.v1";
const ACCEPTED_DECISION_ACCEPTED = "accepted";

// approvedByMemberProposal indexes every approval.approved.v1 by the proposal id
// of each member it sealed: proposal_id -> [{ who, seq }]. A seal of a two-act
// batch names the batch member ids in members[]; the top-level proposal_id is
// the job id, so the correlation is always through members[].proposal_id. A
// single-member approval with no members[] falls back to the top-level id.
function approvedByMemberProposal(events) {
  const byProposal = {};
  for (const ev of events) {
    if (ev.event_type !== "approval.approved.v1") continue;
    const p = decodePayload(ev);
    const approvedBy = p.approved_by_subject || "";
    const s = seq(ev);
    let seenPid = false;
    if (Array.isArray(p.members)) {
      for (const m of p.members) {
        if (!m || typeof m !== "object") continue;
        const pid = String(m.proposal_id || "").trim();
        if (pid) {
          (byProposal[pid] ||= []).push({ who: approvedBy, seq: s });
          seenPid = true;
        }
      }
    }
    if (!seenPid) {
      const pid = String(p.proposal_id || "").trim();
      if (pid) (byProposal[pid] ||= []).push({ who: approvedBy, seq: s });
    }
  }
  return byProposal;
}

function checkTwoAct(events) {
  const r = { check: "two_act_oversight", status: "PASS", count: 0, notes: [], anomalies: [] };
  const approvedByProposal = approvedByMemberProposal(events);
  const policySets = [];
  for (const ev of events) {
    if (ev.event_type !== TENANT_POLICY_SET_EVENT_TYPE) continue;
    const p = decodePayload(ev);
    if (p.policy_key !== AUTHOR_SELF_SEAL_POLICY_KEY) continue;
    policySets.push({ seq: seq(ev), value: p.policy_value, event_id: ev.event_id });
  }

  let acceptedGovernance = 0, sealedBySecond = 0, awaiting = 0;
  let catalogueResolved = 0, policyResolved = 0;
  for (const ev of events) {
    if (ev.event_type !== TWO_ACT_ACCEPTED_EVENT_TYPE) continue;
    const p = decodePayload(ev);
    const acceptedSeq = seq(ev);
    const acceptedBy = p.accepted_by_subject || "";
    const jti = p.approval_jti || "";
    const resolvedSet = authorSelfSealSetAt(policySets, acceptedSeq, p);
    const fromCatalogue = resolvedSet === CATALOGUE_V1_RESOLVED || resolvedSet === CATALOGUE_V2_RESOLVED;
    if (!Array.isArray(p.members)) continue;
    for (const m of p.members) {
      if (!m || typeof m !== "object") continue;
      if (m.decision !== ACCEPTED_DECISION_ACCEPTED) continue;
      const kind = String(m.entity_kind || "").trim().toLowerCase();
      if (kind && resolvedSet.has(kind)) continue;
      acceptedGovernance++;
      if (fromCatalogue) catalogueResolved++; else policyResolved++;
      const pid = String(m.proposal_id || "").trim();
      const seals = (approvedByProposal[pid] || []).filter((x) => x.seq > acceptedSeq);
      if (!seals.length) { awaiting++; continue; }
      seals.sort((a, b) => a.seq - b.seq);
      const sealer = seals[0].who;
      if (sealer && acceptedBy && sealer !== acceptedBy) {
        sealedBySecond++;
      } else {
        r.status = "FAIL";
        r.anomalies.push({
          kind: "two_act_self_seal",
          approval_jti: jti,
          proposal_id: pid,
          entity_kind: kind,
          accepted_by_subject: acceptedBy,
          sealed_by_subject: sealer,
          message: "a governance record was accepted AND sealed by the same OIDC subject (" + (acceptedBy || "unknown") + "); the tenant keeps a second person on this kind, so a different reviewer had to seal what the author accepted - the two-act oversight was not satisfied",
        });
      }
    }
  }

  r.count = acceptedGovernance;
  if (acceptedGovernance === 0) {
    r.notes.push("no governance records were parked for a second person in this bundle; nothing to check");
    return r;
  }
  const basis = [];
  if (catalogueResolved) basis.push(catalogueResolved + " resolved against the catalogue-default author-may-self-seal set");
  if (policyResolved) basis.push(policyResolved + " resolved against a tenant policy set on the chain");
  r.notes.push(acceptedGovernance + " governance record" + (acceptedGovernance === 1 ? "" : "s") + " were accepted by their author and required a second person to seal (" + basis.join("; ") + ").");
  if (sealedBySecond) r.notes.push(sealedBySecond + " were sealed by a different reviewer than the person who accepted them - two-act oversight complete.");
  if (awaiting) r.notes.push(awaiting + " accepted and awaiting a second reviewer's seal; this is a normal in-flight state, not an anomaly.");
  return r;
}

// Per-member attestation (the recorded-click regime). Every member of an approval
// produced under the recorded-click regime (attestation_required=true, in the
// hashed payload) must carry a non-empty attestation (a person and non-blank
// words). Gated on the approval's own flag: an approval that predates the regime
// is not asked for attestations and passes unchanged. Kept in lockstep with
// verify.py check_member_attestation.
function attestationOk(member) {
  const att = member && typeof member === "object" ? member.attestation : null;
  if (!att || typeof att !== "object") return false;
  return String(att.by || "").trim() !== "" && String(att.text || "").trim() !== "";
}

function checkMemberAttestation(events) {
  const r = { check: "member_attestation", status: "PASS", count: 0, notes: [], anomalies: [] };
  const gated = events.filter(
    (e) => e.event_type === "approval.approved.v1" && decodePayload(e).attestation_required === true,
  );
  r.count = gated.length;
  if (!gated.length) {
    r.notes.push("no recorded-click approvals in this bundle; nothing to verify");
    return r;
  }
  // M-152: a member whose write was refused has a canonical.write.failed.v1 for
  // that exact approval_jti + proposal_id; nothing was sealed, so nothing to attest.
  const refused = new Set();
  for (const e of events) {
    if (e.event_type !== "canonical.write.failed.v1") continue;
    const fp = decodePayload(e);
    if (fp.approval_jti && fp.proposal_id) refused.add(JSON.stringify([String(fp.approval_jti), String(fp.proposal_id)]));
  }
  let refusedSkipped = 0;
  for (const ev of gated) {
    const p = decodePayload(ev);
    const members = p.members;
    if (!Array.isArray(members) || !members.length) {
      r.status = "FAIL";
      r.anomalies.push({
        kind: "attestation_members_missing",
        event_id: ev.event_id,
        approval_jti: p.approval_jti,
        message: "approval declares a recorded click but lists no members to carry the attestation",
      });
      continue;
    }
    for (const m of members) {
      if (m && typeof m === "object" && refused.has(JSON.stringify([String(p.approval_jti), String(m.proposal_id)]))) {
        refusedSkipped++;
        continue;
      }
      if (!m || typeof m !== "object" || !attestationOk(m)) {
        r.status = "FAIL";
        r.anomalies.push({
          kind: "member_attestation_missing",
          event_id: ev.event_id,
          approval_jti: p.approval_jti,
          proposal_id: m && typeof m === "object" ? m.proposal_id : null,
          entity_kind: m && typeof m === "object" ? m.entity_kind : null,
          message: "a member of a recorded-click approval has no recorded attestation; the chain cannot prove the person ticked and approved this item",
        });
      }
    }
  }
  if (r.status === "PASS") {
    r.notes.push("verified a recorded attestation on every member of " + gated.length + " recorded-click approvals" + (refusedSkipped ? " (" + refusedSkipped + " refused members skipped: no write was sealed)" : ""));
  }
  return r;
}

// DEFAULT_SKILL_KEYS: the pinned first-party skill-signing public key (ECDSA
// P-256), mirrored from trusted_keys.json (skill_signing_keys). A skill
// activation's signature is verified against THESE, never anything the bundle
// ships.
const DEFAULT_SKILL_KEYS = [
  { signing_key_id: "sha256:068fb03acc0367e508ce0da187ccca9d37cdd11c499dc2ae2dd6a2bcda627e84", label: "kanonik-first-party", pem: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExjLB9vqUvtWH8eNCvUpEU5Tlwurm\n4FLNVJABg1P8X+H/4PqnMWwZCRybLPhAnsoLfPmtZ8qvH0oI+WPFMRIIig==\n-----END PUBLIC KEY-----\n" },
];

// ECDSA P-256 verification over a PRE-HASHED digest. The skill signer signs the
// SHA-256 of manifest.yaml and the chain records only that digest
// (manifest_hash), but WebCrypto can only verify over the message itself, so
// this checks the signature with BigInt arithmetic. Verification only: it
// handles public data, so constant-time execution is not needed.
const P256 = {
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};

function modP(x) { const r = x % P256.p; return r >= 0n ? r : r + P256.p; }
function modInv(a, m) {
  let [r0, r1] = [((a % m) + m) % m, m];
  let [t0, t1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [t0, t1] = [t1, t0 - q * t1];
  }
  return ((t0 % m) + m) % m;
}
function p256Add(P, Q) {
  if (!P) return Q;
  if (!Q) return P;
  let lam;
  if (P[0] === Q[0]) {
    if (modP(P[1] + Q[1]) === 0n) return null;
    lam = modP(3n * (P[0] * P[0] - 1n) * modInv(2n * P[1], P256.p));
  } else {
    lam = modP((Q[1] - P[1]) * modInv(Q[0] - P[0], P256.p));
  }
  const x = modP(lam * lam - P[0] - Q[0]);
  return [x, modP(lam * (P[0] - x) - P[1])];
}
function p256Mul(k, P) {
  let R = null;
  let A = P;
  while (k > 0n) {
    if (k & 1n) R = p256Add(R, A);
    A = p256Add(A, A);
    k >>= 1n;
  }
  return R;
}
function bytesToBig(b) { let x = 0n; for (const v of b) x = (x << 8n) | BigInt(v); return x; }

// derSignatureToRS parses a strict ASN.1 DER ECDSA signature
// (SEQUENCE { INTEGER r, INTEGER s }): minimal lengths, positive minimally
// encoded INTEGERs, no trailing bytes. Anything else is null, matching the
// Python verifier's refusal of malformed DER.
function derSignatureToRS(sig) {
  let i = 0;
  const len = () => {
    if (i >= sig.length) return -1;
    let l = sig[i++];
    if (l & 0x80) {
      const n = l & 0x7f;
      if (n < 1 || n > 2 || i + n > sig.length || sig[i] === 0) return -1;
      l = 0;
      for (let k = 0; k < n; k++) l = (l << 8) | sig[i++];
      if (l < 0x80) return -1; // long form is only for lengths >= 128
    }
    return l;
  };
  if (sig[i++] !== 0x30) return null;
  if (len() !== sig.length - i) return null;
  const ints = [];
  for (let k = 0; k < 2; k++) {
    if (sig[i++] !== 0x02) return null;
    const l = len();
    if (l < 1 || i + l > sig.length) return null;
    const body = sig.subarray(i, i + l);
    if (body[0] & 0x80) return null; // negative
    if (l > 1 && body[0] === 0 && !(body[1] & 0x80)) return null; // redundant padding
    ints.push(bytesToBig(body));
    i += l;
  }
  return i === sig.length ? ints : null;
}

// p256VerifyDigest reports whether sigDer is a valid ECDSA-P256 signature by
// the SPKI public key spkiDer over the 32-byte digest.
function p256VerifyDigest(spkiDer, digest, sigDer) {
  if (digest.length !== 32 || spkiDer.length < 65) return false;
  const pt = spkiDer.subarray(spkiDer.length - 65);
  if (pt[0] !== 4) return false;
  const Q = [bytesToBig(pt.subarray(1, 33)), bytesToBig(pt.subarray(33))];
  // The point must lie on the curve (y^2 = x^3 - 3x + b); b is recovered from G.
  const b = modP(P256.gy * P256.gy - P256.gx * P256.gx * P256.gx + 3n * P256.gx);
  if (modP(Q[1] * Q[1]) !== modP(Q[0] * Q[0] * Q[0] - 3n * Q[0] + b)) return false;
  const rs = derSignatureToRS(sigDer);
  if (!rs) return false;
  const [r, s] = rs;
  if (r <= 0n || r >= P256.n || s <= 0n || s >= P256.n) return false;
  const w = modInv(s, P256.n);
  const u1 = (bytesToBig(digest) * w) % P256.n;
  const u2 = (r * w) % P256.n;
  const X = p256Add(p256Mul(u1, [P256.gx, P256.gy]), p256Mul(u2, Q));
  return X !== null && X[0] % P256.n === r;
}

// verifySkillSignature returns the pinned skill key that verifies the
// base64 signature over the digest manifestHash ("sha256:<hex>") names, or
// null. Mirrors verify.py _verify_skill_signature.
function verifySkillSignature(manifestHash, signatureB64, skillKeys) {
  if (!/^sha256:[0-9a-f]{64}$/.test(manifestHash)) return null;
  let digest;
  let sig;
  try {
    digest = Uint8Array.from(manifestHash.slice(7).match(/../g).map((h) => parseInt(h, 16)));
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureB64)) return null;
    sig = b64ToBytes(signatureB64);
  } catch { return null; }
  for (const k of skillKeys) {
    const pem = typeof k.pem === "string" ? k.pem : new TextDecoder().decode(k.pem);
    try {
      if (p256VerifyDigest(pemToDer(pem), digest, sig)) return k;
    } catch { /* try the next pinned key */ }
  }
  return null;
}

export function checkSkillProvenance(events, skillKeys) {
  const r = { check: "skill_provenance", status: "PASS", count: 0, notes: [], anomalies: [] };
  const acts = events.filter((e) => e.event_type === "skill.activated.v1");
  r.count = acts.length;
  if (!acts.length) {
    r.notes.push("no skill activation events in this bundle; nothing to verify");
    return r;
  }
  skillKeys = skillKeys || DEFAULT_SKILL_KEYS;
  const unsigned = new Set();
  let verified = 0;
  for (const ev of acts) {
    const p = decodePayload(ev);
    const sk = `${p.skill_name}@${p.skill_version}`;
    const missing = ["manifest_hash", "signing_identity", "signing_key_id"].filter((f) => !p[f]);
    if (missing.length) {
      r.status = "FAIL";
      r.anomalies.push({ kind: "skill_provenance_fields_missing", event_id: ev.event_id, skill_name: p.skill_name, skill_version: p.skill_version, missing, message: "skill activation event lacks one or more provenance fields; the chain cannot prove which signed skill produced this work" });
      continue;
    }
    if (!p.manifest_signature) { unsigned.add(sk); continue; }
    const matched = verifySkillSignature(String(p.manifest_hash), String(p.manifest_signature), skillKeys);
    if (!matched) {
      r.status = "FAIL";
      r.anomalies.push({ kind: "skill_signature_invalid", event_id: ev.event_id, skill_name: p.skill_name, skill_version: p.skill_version, message: "the signature recorded on this skill activation does not verify over its manifest hash against a pinned Kanonik skill-signing key (trusted_keys.json); the instruction set cannot be attributed to a signed Kanonik skill" });
    } else if (matched.signing_key_id !== p.signing_key_id) {
      r.status = "FAIL";
      r.anomalies.push({ kind: "skill_signing_key_mismatch", event_id: ev.event_id, skill_name: p.skill_name, skill_version: p.skill_version, message: "the signature verifies, but under a different pinned key than the signing key id this activation records" });
    } else {
      verified++;
    }
  }
  if (unsigned.size) {
    if (r.status === "PASS") r.status = "DEGRADED";
    r.notes.push("these AI instruction sets are recorded by name and version but carry no signature this tool can verify against a pinned Kanonik skill-signing key: " + [...unsigned].sort().join(", ") + ". Their identity and version are on the chain and are tamper-evident, but the signing authority cannot be confirmed.");
  }
  if (r.status === "PASS") {
    r.notes.push(`verified the signature on ${verified} skill activation events against the pinned first-party skill-signing key`);
  }
  return r;
}

const REQUIRED = ["canonical_inputs_hash", "prompt_version", "prompt_hash"];
// retrieved_context_hash is NOT required: the direct graders fold the retrieved
// requirements into canonical_inputs_hash, so an empty value is honest and
// complete. Reported as a NOTE below, like seed. Mirrors verify.py.
const LLM_REQUIRED = ["model_provider", "model_id"];
// An EMBEDDED verdict carries its tuple in a nested `metadata` object with
// different field names (prompt_content_hash, model). The metadata schema
// requires these four on every verdict, so absence is malformed -> FAIL;
// canonical_inputs_hash / retrieved_context_hash / seed are omitempty (forward-
// compatible with older verdicts) -> NOTE. Mirrors verify.py.
const EMBEDDED_REQUIRED = ["prompt_version", "prompt_content_hash", "model_provider", "model"];

function checkReproducibilityTuple(events) {
  const r = { check: "reproducibility_tuple_completeness", status: "PASS", count: 0, notes: [], anomalies: [] };
  const verdicts = events.filter((e) => e.event_type === "verifier.verdict.v1");
  // Embedded verdicts inside committed events must be replay-checked too; this
  // check historically saw only standalone verdicts, so an embedded verdict
  // missing its tuple slipped through.
  const embeddedPairs = [];
  for (const e of events) {
    if (!COMMITTED.has(e.event_type)) continue;
    const ev = decodePayload(e).verifier_verdict;
    if (ev && typeof ev === "object") embeddedPairs.push([e, ev]);
  }
  r.count = verdicts.length + embeddedPairs.length;
  if (!verdicts.length && !embeddedPairs.length) {
    r.notes.push("no verifier verdicts in this bundle; nothing to verify");
    return r;
  }
  let seedMissing = 0;
  let retrievedHashMissing = 0;
  for (const v of verdicts) {
    const p = decodePayload(v);
    const missing = REQUIRED.filter((f) => !p[f]);
    if (missing.length) {
      r.status = "FAIL";
      r.anomalies.push({ kind: "reproducibility_tuple_incomplete", event_id: v.event_id, missing, message: "Verifier verdict missing replay fields; the decision record is incomplete" });
      continue;
    }
    if (p.tier === "llm") {
      const lm = LLM_REQUIRED.filter((f) => !p[f]);
      if (lm.length) {
        r.status = "FAIL";
        r.anomalies.push({ kind: "llm_tier_tuple_incomplete", event_id: v.event_id, missing: lm, message: "LLM-tier verdict missing model_provider / model_id; the decision record is incomplete" });
        continue;
      }
      if (!p.seed) seedMissing++;
      if (!p.retrieved_context_hash) retrievedHashMissing++;
    }
  }
  // Embedded verdicts: the tuple lives in the nested `metadata` (different
  // names). A missing required field is a malformed verdict -> FAIL; the
  // omitempty fields are a note.
  let embInputsMissing = 0;
  let embSeedMissing = 0;
  let embRetrievedMissing = 0;
  for (const [c, ev] of embeddedPairs) {
    const md = ev.metadata;
    if (!md || typeof md !== "object") {
      r.status = "FAIL";
      r.anomalies.push({ kind: "embedded_verdict_metadata_missing", event_id: c.event_id, event_type: c.event_type, message: "the verdict embedded in this committed event carries no metadata envelope; the decision record is incomplete" });
      continue;
    }
    const missing = EMBEDDED_REQUIRED.filter((f) => !md[f]);
    if (missing.length) {
      r.status = "FAIL";
      r.anomalies.push({ kind: "embedded_reproducibility_tuple_incomplete", event_id: c.event_id, event_type: c.event_type, missing, message: "embedded Verifier verdict missing required replay fields (prompt_version / prompt_content_hash / model / model_provider); the decision record is incomplete" });
      continue;
    }
    if (!md.canonical_inputs_hash) embInputsMissing++;
    if (!md.seed) embSeedMissing++;
    if (!md.retrieved_context_hash) embRetrievedMissing++;
  }
  if (embeddedPairs.length) r.notes.push(`walked ${embeddedPairs.length} embedded verdicts inside committed events for the replay tuple (metadata envelope)`);
  if (embInputsMissing) r.notes.push(`${embInputsMissing} embedded verdicts have no canonical_inputs_hash; expected for verdicts sealed before that field existed (omitempty, forward-compatible) - a note, not a fail`);
  if (embSeedMissing || embRetrievedMissing) r.notes.push(`${embSeedMissing} embedded verdicts have no seed and ${embRetrievedMissing} no separate retrieved_context_hash; expected (provider seedless / retrieval folded into canonical_inputs_hash)`);
  if (seedMissing) r.notes.push(`${seedMissing} LLM-tier verdicts have no seed (expected when the provider does not accept one)`);
  if (retrievedHashMissing) r.notes.push(`${retrievedHashMissing} LLM-tier verdicts have no separate retrieved_context_hash (expected for the direct graders, which fold the retrieved requirements into canonical_inputs_hash; still records the prompt version, model and canonical_inputs_hash; the prompt text stays with Kanonik)`);
  if (r.status === "PASS") r.notes.push(`all ${r.count} verdicts (standalone + embedded) carry the required tier-3 reproducibility fields`);
  return r;
}

function checkPromptIntegrity(events, registry) {
  const r = { check: "prompt_integrity", status: "PASS", count: 0, notes: [], anomalies: [] };
  const prompts = registry && registry.prompts;
  if (!prompts || typeof prompts !== "object" || !Object.keys(prompts).length) {
    r.status = "DEGRADED";
    r.notes.push("chain/verifier_prompt_registry.json absent or empty - cannot confirm LLM-tier prompt_hash values against the released prompt set (older bundle). Tuple completeness (check #6) still holds.");
    return r;
  }
  const known = new Set(Object.values(prompts));
  const verdicts = events.filter((e) => e.event_type === "verifier.verdict.v1");
  let checked = 0;
  for (const v of verdicts) {
    const p = decodePayload(v);
    const pv = String(p.prompt_version || "");
    if (p.tier !== "llm" || pv.endsWith("-stub")) continue;
    checked++;
    if (!known.has(p.prompt_hash || "")) {
      r.status = "FAIL";
      r.anomalies.push({ kind: "llm_prompt_not_recognized", event_id: v.event_id, prompt_version: pv, prompt_hash: p.prompt_hash, message: "LLM-tier verdict cites a prompt_hash that is NOT a released Kanonik Verifier prompt - fabricated or tampered" });
    }
  }
  // Embedded verdicts (inside committed events) cite their released prompt in
  // nested metadata.prompt_content_hash - a DIFFERENT field name than the
  // standalone prompt_hash. Validate each PRESENT one against the SAME released
  // registry. A genuine embedded verdict cites a released prompt whose content
  // hash is in this registry, so a real bundle passes. An ABSENT hash is left to
  // the reproducibility check; '-stub' prompt versions are carved out. MUST stay
  // identical to verify.py check_prompt_integrity.
  let embeddedChecked = 0;
  for (const e of events) {
    if (!COMMITTED.has(e.event_type)) continue;
    const ev = decodePayload(e).verifier_verdict;
    if (!ev || typeof ev !== "object" || Array.isArray(ev)) continue;
    const md = ev.metadata;
    if (!md || typeof md !== "object") continue;
    const pv = String(md.prompt_version || "");
    if (pv.endsWith("-stub")) continue;
    const pch = md.prompt_content_hash || "";
    if (!pch) continue;
    embeddedChecked++;
    if (!known.has(pch)) {
      r.status = "FAIL";
      r.anomalies.push({ kind: "embedded_llm_prompt_not_recognized", event_id: e.event_id, event_type: e.event_type, prompt_version: pv, prompt_content_hash: pch, message: "embedded Verifier verdict cites a prompt_content_hash that is NOT a released Kanonik Verifier prompt (absent from the bundle's chain/verifier_prompt_registry.json); the recorded verdict did not use a genuine released prompt - fabricated or tampered" });
    }
  }
  r.count = checked + embeddedChecked;
  if (r.status === "PASS") {
    r.notes.push(r.count === 0
      ? "no LLM-tier verdicts in this bundle; nothing to verify against the prompt registry"
      : `verified ${checked} standalone + ${embeddedChecked} embedded verdict prompt hash value(s) against the released Verifier prompt registry`);
  }
  return r;
}

const PACKAGE_SEAL_FILE = "package_seal.json";
const PACKAGE_SEAL_VERSION = "kanonik.package-seal.v1";
const UNSEALED_NOTE =
  "the files of this package are not sealed in this package version: MANIFEST.json is not signed, so a file " +
  "changed together with its listed checksum cannot be detected here. Each file still matches its listed " +
  "checksum. Ask for a current package";
const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
// A file an operating system or a run of the Python checker may leave beside the package is not package content.
// The checker's bytecode is exempt only where the checker lives (chain/__pycache__/*.pyc); a __pycache__ folder
// anywhere else is a place to hide a document, and fails.
const isPackageNoise = (rel) => {
  const last = rel.split("/").pop();
  return last === ".DS_Store" || last === "Thumbs.db" || last === "desktop.ini" || /^(?:Verification\/)?chain\/__pycache__\/[^/]+\.pyc$/.test(rel);
};

// Mirror verify.py check_package_seal. Mutates r.
const SEAL_REMOVED_MESSAGE =
  "this package was exported with a seal (its signed chain root says so) but the seal file is missing: the seal " +
  "was removed, or files were changed and the seal with them. Do not rely on this package.";
const PREDATES_SEAL_MESSAGE =
  "this package carries a chain root from before packages were sealed, signed after the day Kanonik began " +
  "sealing them: it was exported by an older version, or its root was swapped. Ask for a current package.";
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
// Whole seconds since the epoch of an RFC 3339 instant, or null. The fraction is ignored: the instants compared are whole seconds.
function instantSeconds(value) {
  if (typeof value !== "string") return null;
  const m = RFC3339.exec(value.trim());
  if (!m) return null;
  const [y, mo, d, h, mi, sec] = m.slice(1, 7).map(Number);
  const ms = Date.UTC(y, mo - 1, d, h, mi, sec);
  const probe = new Date(ms);
  if (probe.getUTCFullYear() !== y || probe.getUTCMonth() !== mo - 1 || probe.getUTCDate() !== d || probe.getUTCHours() !== h || probe.getUTCMinutes() !== mi || probe.getUTCSeconds() !== sec) return null;
  let offset = 0;
  if (m[7] !== "Z") offset = (Number(m[7].slice(1, 3)) * 3600 + Number(m[7].slice(4, 6)) * 60) * (m[7][0] === "+" ? 1 : -1);
  return Math.floor(ms / 1000) - offset;
}
// Does the package claim to be sealed, by something that cannot change without breaking a signature? Returns null
// (no claim: an older package), "v3" (the root's version says so) or "predates" (signed by a pinned key from the day it
// requires seals, yet not a v3 root). Mirrors verify.py seal_claim, including enforcing a v3 claim even when the
// signature cannot be checked here.
async function sealClaim(root, trustedKeys) {
  if (!root || typeof root !== "object") return null;
  const version = String(root.version || root.Version || "v1");
  if (version === CHAIN_ROOT_V3) return "v3";
  if (!root.signature || !trustedKeys || !trustedKeys.some((k) => k.seal_required_from)) return null;
  let dates;
  try {
    // Every pinned entry whose key verifies the signature counts, and the EARLIEST date among them wins: the policy
    // must not depend on which of two entries for one key comes first in the list. Mirrors verify.py.
    const sigRaw = derToRawEcdsa(strictRootB64(root.signature), 48);
    const signedBytes = chainRootSignedPayload(root);
    dates = [];
    for (const k of await consolidateKeys(trustedKeys)) if (await verifySigAgainstTrusted(sigRaw, signedBytes, [k])) dates.push(k.seal_required_from || "");
  } catch { return null; }
  dates = dates.filter((d) => d);
  if (!dates.length) return null;
  const signed = instantSeconds(root.signed_at);
  for (const d of dates) {
    const required = instantSeconds(d);
    if (required === null || signed === null || signed >= required) return "predates"; // an unreadable date fails closed
  }
  return null;
}

async function checkPackageSeal(sealBytes, manifest, manifestBytes, files, machine, root, trustedKeys, publicKeyPem, r) {
  const exactKeys = (v, keys) => v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).sort().join(",") === [...keys].sort().join(",");
  const strictB64 = (x) => {
    if (typeof x !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(x) || x.length % 4) throw new Error("invalid base64");
    return b64ToBytes(x);
  };
  let payload, payloadBytes, signature, rootBytes;
  try {
    const envelope = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(sealBytes));
    if (!exactKeys(envelope, ["payload", "signature"])) throw new Error("expected a payload and signature envelope");
    payloadBytes = strictB64(envelope.payload);
    signature = strictB64(envelope.signature);
    const payloadText = new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes);
    payload = JSON.parse(payloadText);
    // canonicalMarshal returns the UTF-8 bytes as one character per byte, so compare bytes, not decoded text:
    // a path with a non-ASCII letter must verify here as it does in Python.
    const canonical = Uint8Array.from(canonicalMarshal(payload), (c) => c.charCodeAt(0));
    if (!exactKeys(payload, ["version", "tenant_id", "chain_root_sha256", "signing_key_id", "manifest_sha256", "files"]) ||
        canonical.length !== payloadBytes.length || canonical.some((b, i) => b !== payloadBytes[i])) throw new Error("seal payload must use the canonical schema");
    if (payload.version !== PACKAGE_SEAL_VERSION) throw new Error("unknown package seal signing domain");
    if (!root || !root.signature) throw new Error("the seal needs the signed chain root of this package");
    rootBytes = chainRootSignedPayload(root);
    if (payload.chain_root_sha256 !== hex(await sha256(rootBytes))) throw new Error("the seal belongs to a different chain root");
    if (payload.tenant_id !== root.tenant_id || payload.signing_key_id !== root.signing_key_id) throw new Error("the seal's tenant or key differs from the chain root");
    const sealedFiles = payload.files;
    if (!sealedFiles || typeof sealedFiles !== "object" || Array.isArray(sealedFiles) || !Object.keys(sealedFiles).length ||
        !Object.values(sealedFiles).every((v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v))) throw new Error("the sealed file list is malformed");
  } catch (e) {
    r.status = "FAIL";
    r.anomalies.push({ kind: "package_seal_invalid", message: e && e.message ? e.message : String(e) });
    return;
  }
  let independent = true;
  try {
    const sigRaw = derToRawEcdsa(signature, 48);
    const rootSig = derToRawEcdsa(strictB64(root.signature), 48);
    if (trustedKeys && trustedKeys.length) {
      const matched = await verifySigAgainstTrusted(sigRaw, payloadBytes, trustedKeys);
      if (!matched) throw new Error("the package seal is not signed by a pinned Kanonik key: the package, its file list or the seal may have been rebuilt with another key");
      if (!await verifySigAgainstTrusted(rootSig, rootBytes, [matched])) throw new Error("the seal and the chain root must be signed by the same pinned key");
    } else {
      independent = false;
      if (!publicKeyPem) throw new Error("no pinned key and no key in the package; cannot check the seal");
      const own = [{ pem: publicKeyPem }];
      if (!await verifySigAgainstTrusted(sigRaw, payloadBytes, own)) throw new Error("the package seal signature does not verify");
      if (!await verifySigAgainstTrusted(rootSig, rootBytes, own)) throw new Error("the seal and the chain root must be signed by the same key");
    }
  } catch (e) {
    r.status = "FAIL";
    r.anomalies.push({ kind: "package_seal_invalid", message: e && e.message ? e.message : String(e) });
    return;
  }
  if (!independent && r.status === "PASS") {
    r.status = "DEGRADED";
    r.notes.push("the package seal was verified only against the key the package carries, not a pinned Kanonik key");
  }
  const fail = (kind, path, message) => { r.status = "FAIL"; r.anomalies.push(path === undefined ? { kind, message } : { kind, path, message }); };
  if (hex(await sha256(manifestBytes)) !== payload.manifest_sha256) {
    fail("manifest_changed", undefined, "MANIFEST.json is not the file that was sealed: it was changed after the package was made");
  }
  const sealed = payload.files;
  const listed = manifest.file_checksums || {};
  for (const rel of [...new Set([...Object.keys(sealed), ...Object.keys(listed)])].sort()) {
    if (!Object.hasOwn(sealed, rel)) fail("file_not_sealed", rel, "MANIFEST.json lists a file the seal does not cover");
    else if (!Object.hasOwn(listed, rel)) fail("file_removed_from_list", rel, "the seal covers a file MANIFEST.json no longer lists");
    else if (listed[rel] !== sealed[rel]) fail("checksum_not_sealed", rel, "MANIFEST.json lists a checksum for this file that differs from the sealed one");
  }
  for (const [rel, want] of Object.entries(sealed)) {
    const bytes = files.get(rel);
    if (bytes === undefined) fail("sealed_file_missing", rel, "a sealed file is not in the package");
    else if (hex(await sha256(bytes)) !== want) fail("sealed_file_changed", rel, "this file differs from the file that was sealed");
  }
  const skip = new Set([machine + "MANIFEST.json", machine + PACKAGE_SEAL_FILE]);
  for (const rel of [...files.keys()].sort()) {
    if (skip.has(rel) || rel === "" || rel.endsWith("/") || isPackageNoise(rel) || Object.hasOwn(sealed, rel)) continue;
    fail("file_not_sealed", rel, "this file is in the package but was not sealed");
  }
  if (!r.anomalies.length) r.notes.push(`the package seal verified: Kanonik's key signed the file list, and all ${Object.keys(sealed).length} files match it`);
}

async function checkFileChecksums(files, manifest, sealBytes, manifestBytes, root, trustedKeys, publicKeyPem, machine = "") {
  const r = { check: "file_checksums", status: "PASS", count: 0, notes: [], anomalies: [] };
  if (!manifest) {
    r.status = "FAIL";
    r.anomalies.push({ kind: "manifest_missing", message: "MANIFEST.json missing from bundle" });
    return r;
  }
  const minimum = manifest.min_verifier_version;
  if (minimum !== undefined && minimum !== null &&
      (typeof minimum !== "string" || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(minimum) ||
       versionGreater(minimum, MAX_SUPPORTED_BUNDLE_REQUIREMENT))) {
    r.status = "FAIL";
    r.anomalies.push({ kind: "bundle_requirement_unsupported", message: "This bundle requires checks not supported by this toolkit. Ask for a compatible checker." });
    return r;
  }
  const sums = manifest.file_checksums || {};
  r.count = Object.keys(sums).length;
  for (const [path, want] of Object.entries(sums)) {
    const bytes = files.get(path);
    if (bytes === undefined) {
      r.status = "FAIL";
      r.anomalies.push({ kind: "file_missing", path, message: "MANIFEST references file not in bundle" });
      continue;
    }
    const got = hex(await sha256(bytes));
    if (got !== want) {
      r.status = "FAIL";
      r.anomalies.push({ kind: "checksum_mismatch", path, message: "file content does not match MANIFEST checksum" });
    }
  }
  const claim = await sealClaim(root, trustedKeys);
  if (claim === "predates") {
    r.status = "FAIL";
    r.anomalies.push({ kind: "chain_root_predates_seal", message: PREDATES_SEAL_MESSAGE });
  }
  if (sealBytes === undefined) {
    if (claim === "v3") {
      r.status = "FAIL";
      r.anomalies.push({ kind: "seal_removed", message: SEAL_REMOVED_MESSAGE });
    } else if (r.status === "PASS") {
      r.status = "DEGRADED";
      r.notes.push(UNSEALED_NOTE);
    }
    return r;
  }
  await checkPackageSeal(sealBytes, manifest, manifestBytes || new Uint8Array(), files, machine, root, trustedKeys, publicKeyPem, r);
  if (r.status === "PASS" && !r.notes.some((n) => n.includes("seal verified"))) r.notes.push(`verified SHA-256 checksums on ${r.count} files`);
  return r;
}

// ── orchestration ────────────────────────────────────────────────────────────

const dec = new TextDecoder();
const readJson = (files, path) => {
  const b = files.get(path);
  if (!b) return null;
  try {
    return JSON.parse(dec.decode(b));
  } catch {
    return null;
  }
};
const readJsonl = (files, path) => {
  const b = files.get(path);
  if (!b) return [];
  return dec
    .decode(b)
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l));
};

// Human-readable result words. The JSON report keeps PASS / DEGRADED / FAIL
// exactly; only text shown to a person uses these. Mirrors verify.py.
export const RESULT_WORDS = { PASS: "Passed", DEGRADED: "Passed with notes", FAIL: "Failed" };
export function resultWord(status) { return RESULT_WORDS[status] || status; }

// packageCode: first 12 hex chars of the signed chain head
// (chain_root.head_event_hash, base64 of 32 raw bytes), upper-case, grouped
// 4-4-4. "" when there is no head. Mirrors verify.py package_code.
export function packageCode(chainRoot) {
  const head = chainRoot && chainRoot.head_event_hash;
  if (typeof head !== "string" || !head) return "";
  let bytes;
  try { bytes = b64ToBytes(head); } catch { return ""; }
  const h = [...bytes.slice(0, 6)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  if (h.length < 12) return "";
  return h.slice(0, 4) + "-" + h.slice(4, 8) + "-" + h.slice(8, 12);
}

// verifyBundle takes a Map<path, Uint8Array> of the bundle's files and returns
// the same summary shape verify.py prints on stdout.
// resolveLayout mirrors verify.py resolve_layout. The old package keeps
// MANIFEST.json, events.jsonl and the rest of the machine part at the root. The new one puts the
// machine part under Verification/ and lists every file of the package in MANIFEST.json by its path
// from the package folder. A .tar.gz that unpacks into one folder has that folder taken off first.
// Returns the files by path from the package folder and the folder the machine part is read from.
export function resolveLayout(files) {
  if (!files.has("MANIFEST.json") && !files.has("Verification/MANIFEST.json")) {
    const tops = new Set();
    for (const p of files.keys()) {
      const i = p.indexOf("/");
      tops.add(i < 0 ? "" : p.slice(0, i));
    }
    if (tops.size === 1 && !tops.has("")) {
      const top = [...tops][0] + "/";
      if (files.has(top + "MANIFEST.json") || files.has(top + "Verification/MANIFEST.json")) {
        const inner = new Map();
        // The top folder's own tar entry ("pkg/") is a directory, not a file: it has no name once the folder is folded away.
        for (const [p, b] of files) if (p !== top) inner.set(p.slice(top.length), b);
        files = inner;
      }
    }
  }
  // Two manifests: one could list fewer files than the other. Never pick one silently.
  if (files.has("MANIFEST.json") && files.has("Verification/MANIFEST.json")) return { files, machine: "", ambiguous: true };
  if (files.has("Verification/MANIFEST.json")) {
    // Nested manifest: a new-layout package only when it lists files under Verification/. A flat package unpacked into a
    // folder named Verification lists them at its root: take that folder off, as for any single top folder.
    let lists = false;
    try {
      const sums = JSON.parse(dec.decode(files.get("Verification/MANIFEST.json"))).file_checksums;
      lists = !!sums && typeof sums === "object" && Object.keys(sums).some((k) => k.startsWith("Verification/"));
    } catch { lists = false; }
    if (lists) return { files, machine: "Verification/" };
    const inner = new Map();
    for (const [p, b] of files) if (p.startsWith("Verification/")) inner.set(p.slice("Verification/".length), b);
    return { files: inner, machine: "" };
  }
  return { files, machine: "" };
}

export async function verifyBundle(input, opts = {}) {
  const { files, machine, ambiguous } = resolveLayout(input);
  if (ambiguous) {
    const bad = { check: "file_checksums", status: "FAIL", count: 0, notes: [], anomalies: [{ kind: "ambiguous_layout", message: "ambiguous package: MANIFEST.json at the root and in Verification/" }] };
    return { schema_version: "v1", verifier_version: VERIFIER_VERSION, overall_status: "FAIL", summary: { PASS: 0, FAIL: 1, DEGRADED: 0 }, checks: [bad] };
  }
  const manifest = readJson(files, machine + "MANIFEST.json");
  const events = readJsonl(files, machine + "events.jsonl");
  const chainRoot = readJson(files, machine + "chain_root.json");
  const pemBytes = files.get(machine + "public_key.pem");
  const pem = pemBytes ? dec.decode(pemBytes) : null;
  const registry = readJson(files, machine + "chain/verifier_prompt_registry.json");
  const trustedKeys = [...DEFAULT_TRUSTED_KEYS, ...(opts.trustedKeys || [])];

  const results = [];
  const sessionDoc = readJson(files, machine + "session_checkpoints.json");
  const sessionMode = files.has(machine + "session_checkpoints.json");
  results.push(await checkHashChain(events, sessionMode ? (sessionDoc === null ? {} : sessionDoc) : null, trustedKeys, chainRoot, manifest));
  const withheldReport = await checkWithheldPositions(events, files.get(machine + "withheld_positions.json"), chainRoot, trustedKeys);
  if (withheldReport) results.push(withheldReport);
  results.push(checkChainCompleteness(events, chainRoot, sessionMode));
  results.push(await verifyChainRootSignature(chainRoot, pem, events, trustedKeys, sessionMode));
  results.push(checkVerdictPresence(events));
  results.push(checkSoD(events));
  results.push(checkTwoAct(events));
  results.push(checkMemberAttestation(events));
  results.push(checkSkillProvenance(events, opts.skillKeys));
  results.push(checkReproducibilityTuple(events));
  results.push(checkPromptIntegrity(events, registry));
  results.push(await checkFileChecksums(files, manifest, files.get(machine + PACKAGE_SEAL_FILE), files.get(machine + "MANIFEST.json"), chainRoot, trustedKeys, pem, machine));

  const byStatus = { PASS: 0, FAIL: 0, DEGRADED: 0 };
  for (const r of results) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
  const overall = byStatus.FAIL > 0 ? "FAIL" : byStatus.DEGRADED > 0 ? "DEGRADED" : "PASS";
  return { schema_version: "v1", verifier_version: VERIFIER_VERSION, overall_status: overall, summary: byStatus, checks: results };
}

// ── tar.gz extraction (web-standard DecompressionStream + inline tar parse) ───

async function gunzip(bytes) {
  const ds = new DecompressionStream("gzip");
  const stream = new Blob([bytes]).stream().pipeThrough(ds);
  const chunks = [];
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return concatBytes(chunks.map((c) => new Uint8Array(c)));
}

function paxPath(body) {
  const td = new TextDecoder();
  let path = null;
  let pos = 0;
  while (pos < body.length) {
    let sp = pos;
    while (sp < body.length && body[sp] !== 0x20) sp++;
    const lenToken = td.decode(body.subarray(pos, sp));
    const len = /^[0-9]+$/.test(lenToken) ? parseInt(lenToken, 10) : NaN;
    if (!(len > sp - pos + 1) || pos + len > body.length || body[pos + len - 1] !== 0x0a) throw new Error("malformed PAX header in the archive");
    const rec = td.decode(body.subarray(sp + 1, pos + len - 1));
    const eq = rec.indexOf("=");
    if (eq > 0 && rec.slice(0, eq) === "path") path = rec.slice(eq + 1);
    pos += len;
  }
  return path;
}

function untar(bytes) {
  const files = new Map();
  const td = new TextDecoder();
  let off = 0;
  let pendingPath = null; // from a PAX extended header (x) or a GNU long name (L) for the next entry
  while (off + 512 <= bytes.length) {
    const header = bytes.subarray(off, off + 512);
    // Two zero blocks mark the end.
    if (header.every((b) => b === 0)) break;
    let name = td.decode(header.subarray(0, 100)).replace(/\0.*$/, "");
    // ustar keeps the front of a long path in a prefix field (a package folder, then Records/<Kind>/).
    if (td.decode(header.subarray(257, 262)) === "ustar") {
      const prefix = td.decode(header.subarray(345, 500)).replace(/\0.*$/, "");
      if (prefix && name) name = prefix + "/" + name;
    }
    const sizeStr = td.decode(header.subarray(124, 136)).replace(/\0.*$/, "").trim();
    const size = parseInt(sizeStr, 8) || 0;
    const type = String.fromCharCode(header[156]);
    off += 512;
    const body = bytes.subarray(off, off + size);
    off += Math.ceil(size / 512) * 512;
    if (type === "x") {
      // PAX records are "<len> <key>=<value>\n" where <len> counts the whole record in bytes; read them by that length,
      // never by newline, so a value that holds a newline or a look-alike "path=" cannot forge an entry's name.
      const p = paxPath(body);
      if (p !== null) pendingPath = p;
      continue;
    }
    if (type === "L") { pendingPath = td.decode(body).replace(/\0.*$/, ""); continue; }
    if (type === "g") continue;
    if (pendingPath !== null) { name = pendingPath; pendingPath = null; }
    if (name) files.set(name, body);
  }
  return files;
}

// loadBundle accepts either a .tar.gz (Uint8Array) or an already-extracted
// Map<path, Uint8Array>. Returns Map<path, Uint8Array>.
export async function loadBundle(input) {
  if (input instanceof Map) return input;
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  // gzip magic 0x1f 0x8b.
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return untar(await gunzip(bytes));
  }
  return untar(bytes);
}

export async function verifyTarGz(input, opts = {}) {
  return verifyBundle(await loadBundle(input), opts);
}
