# Kanonik export checker

Check a Kanonik Auditor Export without Kanonik. This repository holds the checker program, its signing-key list and the fingerprint of the key Kanonik signs with. Everything runs on your computer. It needs no Kanonik account and no Kanonik service, and it keeps working if Kanonik is gone.

## What it checks

A Kanonik Auditor Export is a package of records: what an AI proposed, what a safety check said, who approved it, and a hash chain that links every entry to the one before. The checker reads the package and answers one question: has anything been changed, added, removed or reordered since Kanonik signed it?

It runs eleven checks. The main ones:

- No entry was changed, removed, inserted or reordered (the hash chain holds).
- Kanonik's signature over the chain's latest entry is genuine and comes from a key listed in this repository.
- Every file in the package is the one Kanonik sealed.
- Every write carries a safety-check result, and every approval was made by someone other than the proposer, or records why one person could approve.

The full list, with what each check means, is in `README.txt` in this repository. It is the same document every export carries.

The result is one of three: **Passed**, **Passed with notes**, **Failed**. Passed with notes means nothing was changed but something could not be fully confirmed; the output says what.

The checker proves the package is intact and was sealed by Kanonik's key. It does not prove the records are true, and it is not an audit opinion.

## Run it offline

You need a package (the `.tar.gz` file you were sent) and either Python 3.8 or later, or Node 18 or later.

With Python:

    python3 -m pip install -r requirements.txt     # one library, for the signature check
    python3 verify.py "Company audit package ABCD-1234-5678.tar.gz"

Without the library the checker still runs, and the signature check reads "Passed with notes".

With Node (no install):

    node --input-type=module -e 'import {verifyTarGz,resultWord} from "./verify.mjs"; import {readFileSync} from "node:fs"; const r=await verifyTarGz(new Uint8Array(readFileSync(process.argv[1]))); console.log(resultWord(r.overall_status)); console.log(JSON.stringify(r.checks,null,2))' "Company audit package ABCD-1234-5678.tar.gz"

The program never connects to the internet unless you pass `--online`.

An exit code of 0 means Passed. Passed with notes and Failed both exit 1, so a script cannot mistake a note for a clean pass.

## Compare the fingerprint

The checker trusts a short list of signing keys that is built into `verify.py`. The one that matters is the production key. Its fingerprint, the SHA-256 of the public key in DER form, is:

    4037e409f864b8149b9f5d021122e1fd2bea3bbec1504a1e2716ba1411c5df1d

Do not take that from this page alone. Compare it in at least two places that do not depend on each other:

1. The README inside the export you are checking prints it.
2. https://kanonik.ai/checker/ publishes it.
3. This repository's `production-key.txt` holds the key. Work the fingerprint out yourself:

        sed -n '/BEGIN PUBLIC/,/END PUBLIC/p' production-key.txt | openssl pkey -pubin -outform der | sha256sum

4. The same key sits in `trusted_keys.json`. Work out its fingerprint with Python:

        python3 -c "import json,base64,hashlib; k=[k for k in json.load(open('trusted_keys.json'))['keys'] if k['env']=='production'][0]; print(hashlib.sha256(base64.b64decode(''.join(l for l in k['pem'].splitlines() if not l.startswith('-----')))).hexdigest())"

All of them must give the same value. If one differs, do not rely on the result, and tell the company that sent you the package.

## Check you have the real files

`SHA256SUMS` lists the eight checker files. In this folder run:

    sha256sum -c SHA256SUMS

(On macOS: `shasum -a 256 -c SHA256SUMS`.) The same files are published at https://kanonik.ai/checker/, and a copy of every export carries them in its `Verification/chain/` folder. A checker from outside the package you are checking is the one that cannot have been re-keyed together with it.

## What is here

- `verify.py`, `verify.mjs`: the checker, in Python and in JavaScript. They give the same results.
- `canonical_json.py`, `event_hash.py`: helpers `verify.py` uses to recompute each entry's hash.
- `trusted_keys.json`: the signing keys the checker trusts, as a file to compare.
- `verifier_prompt_registry.json`: SHA-256 hashes of the released safety-check prompts (hashes only, no prompt text).
- `requirements.txt`: the one dependency, `cryptography`.
- `README.txt`: the full reference, the same text every export carries.
- `production-key.txt`, `SHA256SUMS`: the key and the file sums.
- `PERMANENCE.md`, `CITATION.cff`: where the permanent archive copy is and how to cite it.

Checker version 2.7.20, from Kanonik product release v0.1.76. The eight checker files are byte for byte the ones in that release.

## Licence

MIT. See `LICENSE`. Read the code; it is the point.
