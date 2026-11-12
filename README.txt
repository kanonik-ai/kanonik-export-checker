# Kanonik Auditor Export - offline verification

**You can check this bundle without asking Kanonik. What you still rely on Kanonik for: the pinned signing keys, the withheld-entries list and the prompt registry in this checker.**

Every claim Kanonik makes about this audit trail - that no event was
tampered with, that every external write passed an independent safety
check, that every approval either came from someone other than the
proposer or discloses why one person had to (a recorded sole-admin
exception, or a routine record kind the tenant's policy lets one person
seal), that every AI decision is recorded with what it was given - is verifiable from
the bundle alone, offline, by running the Python script in this
directory against the data Kanonik shipped. It is a single MIT-licensed
Python file (read it). Its only dependency, `cryptography`, is required
solely for the ECDSA P-384 signature check; every other check runs on
stdlib alone.

This directory ships inside every Kanonik Auditor Export bundle so you
or your LLM can verify integrity OFFLINE, without installing Kanonik
and without any network calls.

The bundle root also contains `README.txt` (where to start) and `records.csv`
(a sampling index of sealed versions and approvals). Both are covered by the
manifest file checksums. Older bundles without these files still verify.
This packaging release does not add the future signed-manifest/provenance
checks. Bundles declaring a minimum checker requirement above 2.7.4 are refused
until those checks ship; the toolkit release number alone does not admit them.

## Verifier version shipped in this bundle: 2.7.22

The verifier in this bundle is version **2.7.22**. Several
capabilities have a minimum reading version:

- A **single-record proof** (one sealed record a company handed you as a
  `proof-<kind>-<id>.json` file, checked with `--record`) is read from version
  **2.4.0**. The file itself names the oldest verifier that reads it; an older
  copy refuses it rather than guessing.
- A **saved answer or answer set** sealed by its author alone (the two record
  kinds behind a questionnaire) verifies from version **2.3.0**.
- A **migration summary** (the bounded population of a legacy tool's export
  carried into the record: tool, export hash, operator, date, counts) is a
  rule-tier-only record the author seals alone; it verifies from version
  **2.6.0**, as do the obligation and lens kinds from **2.5.0**.
- A **risk or a remediation** sealed by its author alone verifies from version
  **2.7.0**. A risk entry and a corrective action need an owner, not a second
  signature; a risk acceptance and an exception still need a second person.
- A record the Verifier marked **not assessed** (it made no claim to judge)
  and a person approved through the gate verifies from version **2.7.1**. It
  seals on the ordinary click; without a recorded approver it still fails.
  A record of this kind sealed **before** that change carries a safety-check
  entry that cannot be told apart from an unlabelled rejection, so it still
  fails, by design: the verifier stays strict rather
  than guess. Records sealed after the change verify cleanly when an approver is recorded.
- An **operational fact** (one declared fact about a vendor or an asset,
  graded for soundness and sealed by a second person) verifies from version
  **2.7.2**; an older copy fails it as an unclassified committed kind.
- A **skill activation** carries the signature on the AI instruction set it
  loaded, and the verifier checks it against the pinned Kanonik skill-signing
  key (`skill_signing_keys` in `chain/trusted_keys.json`) from version
  **2.7.3**. A signature that does not verify fails; an activation recorded
  without one is reported as degraded, never as verified.
- **Every gated write** is classified from version **2.7.4**. The decisions a
  person makes with no model output to grade (evidence capture, control test,
  risk acceptance, remediation, exception, conformance attestation) are listed
  in the report as carrying no model verdict by design; an audit session is
  checked for its verdict (reported as degraded when a session sealed before
  verdicts were recorded carries none); any other event that carries an approval token
  and an approver and that this copy does not know fails the check. An older
  copy skips these events without saying so.
- A record sealed over a **rejected** Verifier verdict, and a sole-administrator
  self-approval, are held to the chain from version **2.7.4**. The rejection
  stands only with a separate `approval.override.recorded.v1` event on the chain
  (it names the record, the approver and a reason); a flag inside the record
  itself is not accepted. The sole-administrator exception stands only when the
  chain's own role events show exactly one active administrator at that
  approval, taking each role's effective dates into account; a bundle without
  role events reports it as degraded instead of passing it. A record sealed
  over a rejection before overrides were chain-anchored, which carries only a
  flag inside the record, is reported as degraded (not independently
  attestable) and never as passed; once the chain shows overrides were being
  written, a record without one fails.
- A bundle that **withholds events** outside your access (your company's
  commercial relationship with Kanonik: billing, invoices, seat charges,
  discount and comp codes) verifies from version **2.7.4**. A withheld entry
  keeps its place in the chain and its hash but shows no content. The verifier
  confirms the hash, the link to the entries on both sides and the signature,
  and refuses a withheld marker on an entry that still carries content. An
  older copy fails such a bundle on the hash check; it never passes it.
  Versions 2.7.4 and 2.7.5 report the withheld entries as **DEGRADED**, never
  PASS, because bundles then carried no signed statement of which entries may
  be withheld. From 2.7.8, see the next bullet but one.
- **Result words, counts** (version **2.7.5**): the printed result reads
  Passed / Passed with notes / Failed, and the checker version and package
  code are printed. The self-approval notes count each approval once, however
  many events it carries, and the approvals summary counts a rejection of a
  single item in a request as a rejection of that approval. These change
  wording and counts only; no check's pass or fail changed, and an older copy
  gives the same verdicts.
- A bundle that **withholds commercial events** carries a separately signed
  `withheld_positions.json` from toolkit **2.7.8**. The `withheld_positions`
  check verifies that the exact same pinned key signed the chain root and the
  list of withheld positions, and that the list matches their sequence numbers,
  original hashes and domain. A valid statement reports **PASS**, naming how
  many positions were withheld. Their content is outside your access and was
  not examined. The chain links and every other check still run.
  A changed list, a foreign-key signature or a relabelled compliance event
  **FAILs**. A missing statement retains **DEGRADED**, as before 2.7.8; request a
  fresh export from the company. Malformed statements FAIL. Versions before
  2.7.4 fail the withheld entry's hash check. Use the tools in the current bundle.

- A **record-kind self-seal** (one person accepting AND sealing a routine
  record such as evidence, a control test, or a mapping, that the tenant's
  author-may-self-seal policy permits without a second reviewer) requires
  verifier version **2.0.0 or later**. An older 1.x copy reads those
  approvals as separation-of-duties failures because it predates the rule.
- A **two-act oversight trail** (a governance record one person accepted and a
  second person sealed) is checked from version **2.1.0**. An older 2.0.0 copy
  still verifies a two-act export - it simply does not run the extra oversight
  check that confirms the sealer was a different person than the accepter.

- **Result words** (version **2.7.21**, words only; no check, no report field and no pass or
  fail outcome changed, an older copy gives the same verdicts): the notes under
  `verifier_verdict_presence` name each record kind in words and give a plain reason;
  the printed result says once that the JSON's DEGRADED reads "Passed with notes", and a
  signature that verified with notes, or could not be checked here, reads "not fully";
  the cards of `chain_completeness`, `two_act_oversight` and `member_attestation` in
  `verify.html` say what each check proves.

- **A refined record's verdict, found by what was graded** (version **2.7.22**): a control,
  procedure or policy the AI re-proposed after the safety check's refinement loop is sealed
  under ids that no longer match the id its standalone verdict names, so an older copy reads
  it as sealed without a verdict (`committed_without_verdict`). From 2.7.22, when no id pairs
  the record, the verdict is also matched on what the sealed commit itself records: the same
  inputs hash, prompt content hash, model and rule pack (all four must be recorded and equal),
  the same record kind, an earlier position in the chain than the commit, and an earlier
  proposed draft of the same lineage. A verdict is used for one commit only, the earliest in the chain that matches it. Every verdict
  found this way, and any verdict embedded in the commit, must support the write, so a
  rejected one is never hidden by an approved one, and a commit that records no such evidence
  is still reported as sealed without a verdict. The notes under `verifier_verdict_presence`
  say how many records were paired this way. Two readings were made the same in all
  three copies, as `verify.py` always read them and `verify.mjs` and `verify.html` did not: an
  empty list or object in an approver field counts as no approver, and an override reason is
  blank by the same whitespace rule. Nothing else changed.

Every earlier export, and every governance-kind or sole-admin case, verifies
unchanged on the verifier it originally shipped with. This is additive format
evolution, not a break of any air-gapped copy you already hold. The
`verifier_version` field in the JSON report names the version that produced it.

## One record instead of a bundle: `--record`

A company that answered your questionnaire can hand you the proof of one
record behind an answer instead of the whole export: a file named
`proof-<kind>-<id>.json`. It carries the sealed event with every field the
chain hash covers, a record checkpoint (Kanonik's chain-root signer's
signature over that one event's sequence and hash), the AI safety-check
verdict with its replay fields, the human approval, whether a newer sealed
version existed when the file was made, and the oldest verifier that reads
it. Nothing about any other record is in the file.

```bash
python3 ./chain/verify.py --record ./proof-claim-0192b3a0.json
```

Or drop the `.json` onto `verify.html`. Six checks run: schema and version,
event hash recomputed from the record's own bytes, checkpoint signature,
verdict, approval, currency. `record_currency` reads DEGRADED (not FAIL) when
a newer version existed at export time: the record verifies as the version it
is; ask the sender for the current file.

## A disclosure file instead of a bundle: `--disclosure`

A company that publishes text for a buyer (a policy, a procedure, a set of answers, a standing summary, a
sub-processor list, a third-party document, its trust page profile) can hand you a signed disclosure file: a
`kanonik-disclosure/v1` manifest with its signature. It is read from version **2.7.19**. The file names the oldest
verifier that reads it; an older copy refuses it rather than guessing.

```bash
python3 ./chain/verify.py --disclosure ./disclosure.json
python3 ./chain/verify.py --disclosure --online ./disclosure.json   # also asks whether it is still current
```

Or drop the `.json` onto `verify.html`. The headline is one word:

- `VERIFIED`: signed by a pinned production key, unchanged since.
- `VERIFIED_NON_PRODUCTION`: signed by a pinned integration or sample key; sound, not attestable to production.
- `UNKNOWN_ISSUER`: the key id is not one this checker pins. This does not show the file is forged; this checker may
  be older than the key. Get the current checker, or use `--online`.
- `BAD_SIGNATURE`: the key id is pinned but the signature does not verify. The file was changed after signing, was
  signed by another key, or is damaged.
- `KEY_REVOKED`: signed by a key Kanonik has revoked.
- `UNKNOWN_SCHEMA`: a manifest schema or signature version this checker does not read. It is refused, not guessed.
- `VERIFIER_TOO_OLD`: the file needs a newer checker.
- `MALFORMED`: not a disclosure file, or inconsistent.

Exit code 0 only when the overall result is Passed: `VERIFIED` and, with `--online`, a status of current and
active. Anything else is 1, including `VERIFIED` with an unreadable, revoked, expired or superseded status (the
report says which; the signature word still reads `VERIFIED`). 2 when the file cannot be read.

**What it shows.** Kanonik's signing key attested that this text was approved and sealed in the event the manifest
names (`source_event_hash`), and that the text is unchanged since. **What it does not show.** That the text is true,
or that the sealed event exists: unlike a single-record proof, this file does not carry the event, so the checker
cannot recompute its hash.

**Status.** Offline, the status is "not checked". With `--online` the checker asks the public status address named
in the file, only if it is `https://kanonik.ai` or `https://share.kanonik.ai` and the public status path. It reports
two separate facts: the record status (`current`, `needs_review`, `superseded`, `retired`, `unknown`) and the access
state (`active`, `revoked`, `expired`, `unknown`). If the status cannot be read the report says "status unknown,
integrity as shown": the signature result stands. A copy you downloaded before access was revoked still verifies;
the status tells you it has since been withdrawn.

### Key file version 2

`chain/trusted_keys.json` is `kanonik-chain-root-keys/v2`: each key has a `status` (`active`, `retired`, `revoked`;
a missing status is active, and a status this checker does not know is read as revoked). A revoked key fails every
signature it made, in every mode. A retired key no longer signs; what it signed while active still verifies.

The copy Kanonik publishes at the well-known address is a v2 file signed by a pinned production key (`continuity`:
`signed_by`, `signed_at`, `signature` over the canonical JSON of the whole file without `continuity.signature`).
`--online` uses it only when that signature verifies. It may then add a new key (including a new production key) and
move a key's status forward (active, retired, revoked), never back. A revoked key is listed under `revoked_keys` (by
SHA-256 of its public key), not in `keys`. A file without a valid continuity signature, a v1 file, a file with no
schema, or a file signed before `min_key_file_signed_at` in `trusted_keys.json` adds nothing. The report always says
what `--online` did: "Online key file: used", "REJECTED" (with the reason) or "UNREACHABLE"; in the last two, key
revocations were not checked.

## A trust feed instead of a bundle: `--feed`

A company that shows Kanonik items on its own website can re-host the signed trust feed of its public trust page
(`https://share.kanonik.ai/t/{slug}/feed.json`, a `kanonik-trust-feed/v1` file). It is read from version
**2.7.20**. You can check a copy offline; nothing inside `feed` may be changed, but indentation and key order may.

```bash
python3 ./chain/verify.py --feed ./feed.json
python3 ./chain/verify.py --feed ./feed.json --online     # also fetches the live feed and lists what differs
python3 ./chain/verify.py --feed ./feed.json --disclosure ./item.json   # is that item's signed manifest listed in the feed?
```

Or drop the `.json` onto `verify.html` (tick the box to compare with the live feed). In Node, `verify.mjs` exports
`verifyFeedText` and `verifyFeed`. The headline is one word, the same words as `--disclosure` plus one:

- `VERIFIED`, `VERIFIED_NON_PRODUCTION`, `UNKNOWN_ISSUER`, `BAD_SIGNATURE`, `KEY_REVOKED`, `UNKNOWN_SCHEMA`,
  `VERIFIER_TOO_OLD`, `MALFORMED`: as for a disclosure file. A file with a member the format does not list is
  `MALFORMED` (when the signature held) or `BAD_SIGNATURE` (when the member was added after signing). A file over
  1 MiB is refused before it is parsed.
- `STALE`: the signature is good, but this computer's clock is past `valid_until`. The report says "This copy was
  correct on <issued_at>. It is too old to rely on; fetch the current one." Exit code 1.

The report also gives the copy's age and, for each item, its check code and its status words exactly as the copy
states them. Exit code 0 only when the result is `VERIFIED` and the copy is fresh.

**`--online`** fetches the live feed only from `https://share.kanonik.ai/t/{slug}/feed.json` (the address comes from
the file, so any other host or path is not fetched), checks it the same way and lists the differences by item: added,
removed, status changed. If the company has switched the page off the report says "the company no longer publishes
this page". Without `--online` the checker makes no network connection.

**`--feed feed.json --disclosure item.json`** also confirms that the item's signed manifest digest is listed in the
feed (an open line, or the page profile). An on-request line lists no digest, by design.

## Zero-install: open `verify.html` in a browser

Don't want to touch Python? Open **`verify.html`** (in the bundle root)
in any browser and drag the bundle `.tar.gz` onto the page. It runs the
**same 11 checks** (plus a line counting any withheld entries) entirely in your browser - no install, no upload,
no internet - using the browser's built-in cryptography (WebCrypto
ECDSA P-384 for the chain-root signature, `DecompressionStream` to open
the archive). It's a single self-contained file; the verification logic
is `chain/verify.mjs` (also runnable under Node 18+), which is kept
identical in behaviour to `verify.py`. Read either.

## Quick start (human auditor, 60 seconds)

```bash
# 1. Extract the package if you received a .tar.gz (or skip if already extracted).
#    It unpacks into one folder: "<Company> audit package <code>/".
tar -xzf "<Company> audit package <code>.tar.gz" -C ./bundle/

# 2. (Optional) install the one dependency - cryptography - for the
#    chain-root signature check. Hash-chain integrity + every other
#    check work without it.
python3 -m pip install -r "./bundle/<Company> audit package <code>/Verification/chain/requirements.txt"

# 3. Run the verifier on the package folder. Exit 0 = every check passed.
python3 "./bundle/<Company> audit package <code>/Verification/chain/verify.py" "./bundle/<Company> audit package <code>/"
```

The machine part sits in the package's `Verification/` folder, and `MANIFEST.json`
lists every file of the package by its path from the package folder. The checker
also reads the older flat layout (everything at the top of the bundle), so a
package from before the folder layout still verifies; point it at `Verification/`
or at the package folder, either works.

You can also point `verify.py` directly at a `.tar.gz` and it will
extract to a tempdir for you:

```bash
python3 "./extracted/<Company> audit package <code>/Verification/chain/verify.py" "./<Company> audit package <code>.tar.gz"
```

## How the signing key is trusted

The chain-root signature is checked against a pinned allowlist of Kanonik's
real signing keys that is built into `verify.py` (and into `verify.mjs` and
`verify.html`). `chain/trusted_keys.json` is the same list as a file, shipped
so you can diff it against the canonical public verifier source (above);
`verify.py` never reads it as an anchor, so swapping that file changes
nothing. Add your own keys on purpose with `--trusted-keys`. You trust the
list by the same "diff against the canonical copy" mechanism you use to
trust the verifier code itself. When a pinned key is
available (always, since the list is built in),
**this bundle's own `public_key.pem` is not used** for this
check. A holder who edited and re-signed the bundle with their own key
could still ship a `public_key.pem` matching that foreign key; it would
not matter, because the verifier never verifies against it: the signature simply
does not verify against any pinned key, and that FAILs as untrusted
(`chain_root_key_untrusted`).

`public_key.pem` is used only as a last resort, when no pinned key is
available at all (never the case for the built-in list; only if every pinned key were revoked and no `--trusted-keys` /
`--online` result remained): the verifier then checks the signature against this
bundle's own key, and reports the result **DEGRADED**, never PASS,
because that is not an independent check. Pass `--online` to also fetch
`https://kanonik.ai/.well-known/kanonik-chain-root-keys.json` and pick up
a rotated key without waiting for a new verifier release; offline
verification never depends on this. A recognised non-production key
(a test or demonstration key) verifies against the pinned set but reads DEGRADED too,
never production-attested.

## What it checks

Eleven checks run on every bundle. When the bundle withholds entries, the
output adds a twelfth line, `withheld_positions`, which counts them and always
reads "with notes" (see the 2.7.4 entry above).

| # | Check | What it proves |
| --- | --- | --- |
| 1 | `hash_chain_integrity` | No event was inserted, removed, modified, or reordered relative to the others. |
| 2 | `chain_completeness` | The events set is complete: sequence numbers are unique, and (v2 chain roots) the signed tenant event count matches the number of events walked, so nothing was omitted or truncated after signing. |
| 3 | `chain_root_signature` | Kanonik attested to the chain root at the bundled timestamp: its ECDSA P-384 signature over a SHA-384 digest verifies against a PINNED Kanonik key, never against the bundle's own `public_key.pem`. |
| 4 | `verifier_verdict_presence` | Every external write has a non-rejected Verifier verdict in the chain. |
| 5 | `sod_separation_of_duties` | The same OIDC subject did not both propose AND approve any write, unless the chain discloses why one person could: a recorded sole-admin exception, or a routine record kind the tenant's author-may-self-seal policy (resolved from the chain) lets one person seal. |
| 6 | `two_act_oversight` | Every governance record one person only ACCEPTED (parked for a second person) was sealed by a DIFFERENT subject. Routine record kinds sealed with one click need no second person and are not held to this. An accepted record with no seal yet is reported as awaiting confirmation, not a failure. |
| 7 | `member_attestation` | Every member of an approval under the recorded-click regime carries a non-empty attestation (who, and the words they recorded) when the approval's own payload flags that regime. Approvals from before the regime are unaffected. |
| 8 | `skill_provenance` | Every active skill carries its manifest hash, signing identity and signing key ID, and a signature over that manifest hash that verifies against the PINNED Kanonik skill-signing key. An activation with no signature is degraded; a signature that does not verify fails. |
| 9 | `reproducibility_tuple_completeness` | Every Verifier verdict records which prompt and model produced it: the inputs hash, prompt version + hash, and the model provider + id when a model produced it. A standalone verdict with no `canonical_inputs_hash` FAILS this check; a missing seed or retrieved-context hash is only a note. The bundle records which prompt and model were used; the prompt text stays with Kanonik. |
| 10 | `prompt_integrity` | Every LLM-tier Verifier verdict used a genuine released Kanonik Verifier prompt - its `prompt_hash` matches `chain/verifier_prompt_registry.json` (SHA-256 hashes only, no prompt text). A fabricated or tampered prompt FAILs. |
| 11 | `file_checksums` | Kanonik's pinned key signed the SHA-256 of MANIFEST.json and of every file the package lists (`package_seal.json`), and every file matches it. A file changed, added or removed afterwards fails and is named, even when MANIFEST.json was edited to match. A package whose signed chain root says it was exported with a seal (root version `v3`, every export from v0.1.72 on) and has no `package_seal.json` FAILS (`seal_removed`); a chain root with no signature FAILS (`chain_root_unsigned`). An older package with no seal (an export made before the seal) is checked against MANIFEST.json alone and reads Passed with notes, never Passed. |

## Output

Stdout: a JSON report you can pipe into your tools.

```json
{
  "schema_version": "v1",
  "verifier_version": "2.7.22",
  "overall_status": "DEGRADED",
  "summary": {"PASS": 9, "FAIL": 0, "DEGRADED": 2},
  "checks": [{"check": "hash_chain_integrity", "status": "PASS", ...}, ...]
}
```

Stderr: a human-readable summary, led by the trust claim. It uses three
result words: **Passed**, **Passed with notes** (the record is intact and a
note says what to know) and **Failed**. The JSON above keeps the machine words
`PASS`, `DEGRADED` and `FAIL`. The summary also prints the checker version and
the package code (the first 12 hex characters of the signed chain head, in
groups of four), which should match the code on the cover of the package. This
is the output for a synthetic demonstration bundle (trimmed to the
check names; the full run also prints the notes under each check).

```text
You can check this bundle without asking Kanonik. What you still rely on Kanonik for: the pinned signing keys, the withheld-entries list and the prompt registry in this checker.

Bundle verification: Passed with notes
Checker version: 2.7.22
Package code: 8220-88C6-0E1C
Events checked: 517
Signature verified: not fully (read the notes below)
Separation of duties: 6 author-sealed under policy; 6 sole-admin exceptions; 0 dual-controlled
Replay details present: 199 AI decisions

Kanonik Auditor Export - offline verification
==================================================
[passed ] hash_chain_integrity  (517 items)
[passed ] chain_completeness  (517 items)
[notes  ] chain_root_signature  (0 items)
[passed ] verifier_verdict_presence  (115 items)
[passed ] sod_separation_of_duties  (12 items)
[passed ] two_act_oversight  (0 items)
[passed ] member_attestation  (12 items)
[notes  ] skill_provenance  (11 items)
[passed ] reproducibility_tuple_completeness  (199 items)
[passed ] prompt_integrity  (168 items)
[passed ] file_checksums  (138 items)

Overall: Passed with notes  (9 passed, 2 with notes, 0 failed)

The block below is the same result for programs. It says PASS, DEGRADED or FAIL: DEGRADED means Passed with notes.
```

Here `chain_root_signature` carries a note because the signature verified against
a pinned non-production key (expected for a demonstration bundle), and
`skill_provenance` because one AI instruction set carries no signature this
tool can check. A production bundle with every signature verified and no other
note ends `Overall: Passed`.

On a failure, the trust claim still leads - the bundle is what is bad, not
the verification model:

```text
You can check this bundle without asking Kanonik. What you still rely on Kanonik for: the pinned signing keys, the withheld-entries list and the prompt registry in this checker.

Bundle verification: Failed
Checker version: 2.7.22
Package code: not shown (the seal did not verify)
Events checked: 184
Signature verified: no
Separation of duties: 12 author-sealed under policy; 6 dual-controlled
Replay details present: 23 AI decisions
...
```

## Exit codes

- `0` - every check passed (overall Passed).
- `1` - at least one check failed (chain tampered, signature broken,
  SoD breached, etc.) **or** the overall result is Passed with notes
  (DEGRADED; see below). Both give exit code 1: read the printed result
  word, not the code alone.
- `2` - usage error or unreadable bundle.

A `DEGRADED` result (printed as "Passed with notes"; e.g. `cryptography` lib not installed; therefore
the chain-root signature could not be cryptographically checked in
this run) is not a failure of the bundle, but it is not a pass either:
the overall result is Passed with notes and the exit code is `1`, the same as
FAIL, so a script cannot mistake it for a clean pass. Read the overall
status and the summary, which tell you exactly what was degraded, so
you can run a second pass with the lib installed.

## What if a check FAILs?

The JSON report's `checks[].anomalies[]` array enumerates each finding
with `kind`, `message`, and the specific event_id / sequence_number /
file path involved. Hand the JSON to your LLM (or read it yourself);
the `kind` field is a stable enum your tooling can switch on.

## How is this verifier itself trustworthy?

You can read it. The verifier is a single Python script, MIT
licensed, with no network calls. The companion modules
(`canonical_json.py`, `event_hash.py`) are ports of the implementation
Kanonik used to build the chain, and the chain itself checks them:
a divergent port could not reproduce the recorded hashes, so a
PASS on check #1 is evidence the shipped verifier and the chain
builder agree. Every file in this bundle, including the verifier
itself, is pinned by SHA-256 in `MANIFEST.json`, and Kanonik's key signs
that list in `package_seal.json`. The verifier in a package is covered by
that package's seal but cannot vouch for itself: for an independent check,
use a copy from Kanonik's canonical public verifier source.

## Provenance

The guarantees these checks verify are governed by Kanonik's internal
architecture decision records (event store + per-tenant hash chain,
the chain-root signing cryptography, the provenance taxonomy, and the
signed skill-manifest contract). Summaries of the relevant records are
available from Kanonik on request for your working papers.

For the auditor-LLM workflow, see `SKILL.md` in this directory.

## Public sample key

From version **2.7.6**, a signature matching the pinned `class: sample` key always reports **Passed with notes**
(`DEGRADED` in JSON), never `PASS`: "signed with the Kanonik public sample key: synthetic data, not a customer record".
The class takes precedence over the environment label. Removing that trust anchor makes the sample fail.

### Lifecycle verdicts (2.7.7)

Replacement findings and revised applicability decisions require their own embedded
Verifier verdict. Recorded obligations, lens decisions and migration summaries require
a passing rule verdict for that record before its seal. Supersession pointers,
staleness markers, session transitions, licence attestations, package containers
and separation-of-duties disclosures carry no new model judgment and are reported
as exempt. An explicitly malformed or rejected verdict is never ignored.
The six human-decision kinds must name the approver; a token identifier alone does
not identify a person. Exemption from a model verdict is not an audit opinion.

### Audit-session packs (2.7.11)

A pack made by finalising one audit session holds a selection of the workspace's
chain, not a run from the first event, so the links between events have gaps by
design. The pack therefore carries `session_checkpoints.json`: for every event in
`events.jsonl`, the signature of Kanonik's chain-root key over that event's number
and hash. The verifier recomputes each event's hash, checks each checkpoint against
the pinned keys, and fails an event that was edited, reordered, left without a
checkpoint, or checkpointed under a key it does not pin, and a checkpoint whose event
is missing. The number of gaps is stated; it is not a failure. A selection says
nothing about events it does not include: an event taken out together with its own
checkpoint is not detectable from the pack, because nothing signs the list of
events. The manifest is unsigned, so the pack does not prove which session it was
made for. Older copies (2.7.10 and before) fail such a pack on the link check.
