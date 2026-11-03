# AutoCommand - v2026.11.3.1

This release closes a silent back door in the SSTP / kernel-debug allow-lists and
gives you real proof of what the machine looks like - computed from the machine,
never from a preference file.

## What changed

- **Tamper-evident allow-lists.** `allowed_sstp.txt` / `allowed_kerneldebug.txt`
  keep their plain-file format, but every change the app itself makes is now
  hash-pinned (SHA-256) in an append-only ledger under
  `%PROGRAMDATA%\AutoCommand\allowlist-ledger.log` (admin-only write ACL). On
  every load the file is checked against the pin: a "True" written by anything
  other than the app fails secure - enforcement re-arms on the spot and a red
  "Tamper: Allow-list Reverted" alert says what was found. A deleted or garbage
  file fails secure the same way. Absent files always meant "enforce"; that is
  now true for every failure path.
- **Detection is never gated.** Whitelisted surfaces are still probed on every
  sweep; the whitelist now only skips remediation. Whitelisted drift is recorded
  in the ledger (once per clean-to-drift transition) and surfaced amber in-app
  instead of the surface silently disappearing from view.
- **Protected-surfaces verdicts** (Settings > Network Adapter Security). Live
  machine truth per surface, e.g. "SSTP service: stopped + Disabled (Start=4),
  no SSTP miniports present - enforced, verified 09:14:03". Green = verified
  clean, amber = whitelisted drift, red = drift while enforced. Whitelisted
  rows carry a one-click Re-arm button that resumes enforcement and immediately
  re-verifies.
- **Removal completeness is part of the verdict.** The SSTP verdict now
  enumerates the SSTP-family WAN miniports (read-only SetupAPI listing), so
  "removed and stayed removed" is verified, not just the service state.
- **An honest whitelist dialog.** The adapter review prompt now states what
  "No" actually means: AutoCommand stops checking for and removing that
  surface; drift is recorded but NOT remediated; re-arm anytime in Settings.
- **AllowListSelfTest** - 24 offline checks proving the ledger's fail-secure
  paths (absent, seeded, trusted, tampered-by-rewrite, tampered-by-delete,
  garbage, drift-notes-keep-trust, root isolation) and the SSTP/KDNET verdict
  evaluators against synthetic machine states.

## Notes

- Existing allow-list files are adopted on first run (seeded into the ledger),
  so current whitelists keep working; after that, every change is pinned.
- The ledger directory carries an admin-only write ACL. AutoCommand runs
  elevated, so this never gets in the app's way - it is exactly what blocks a
  standard-user process from quietly flipping the allow-lists off.
