# Security

ur-tones carries seeds and transactions. If you find a vulnerability — in
the format (for instance in the seed PIN, SPEC §4) or in an implementation
here (Python, C, the web tool) — please report it privately: use GitHub's
**"Report a vulnerability"** button (Security tab of this repository) rather
than a public issue.

Useful to include: what an attacker can do, how to reproduce it, and the
version (the release tag, or the commit).

## Known limits (not vulnerabilities)

- Transactions and public keys are not encrypted: anyone who hears them can
  read them (they give no access to funds).
- A seed sent without a PIN, or with a short one, can be recovered by
  whoever records it. The PIN slows guessing (PBKDF2), but a short one can
  still be guessed offline.
- ur-tones is a draft and has not been audited.
