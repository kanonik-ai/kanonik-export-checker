# Permanence

This checker is meant to outlast the company that wrote it. A copy is held in the Software Heritage archive, the public, non-profit source code archive run by Inria. It keeps a copy even if this repository is deleted or Kanonik no longer exists.

- Archive address of this repository: https://archive.softwareheritage.org/browse/origin/?origin_url=https://github.com/kanonik-ai/kanonik-export-checker
- Each release is pinned there by a permanent identifier (a SWHID, for example `swh:1:rel:...`). The identifier cannot sit inside the files it identifies, so it is given in the notes of each release on this repository's Releases page and at https://kanonik.ai/checker/.
- To check a copy you hold against the archive: run `sha256sum -c SHA256SUMS`, then compare `SHA256SUMS` with the file of the same name in the archived release.

If you cannot reach Kanonik or kanonik.ai, get the checker from the archive and the fingerprint from `production-key.txt` there, compare it with the one printed in your export's README, and run the checker as described in `README.md`.

To cite: see `CITATION.cff`.
