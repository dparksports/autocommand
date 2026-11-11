# v2026.11.10.5 — Sealing the local-trust doors

Three independent security reviews of this repository (static, line-level,
against v2026.11.3.4) found a consistent theme: the app's own trust boundary
is the user session, and it runs everything as Administrator. Several files
that gate machine-level capabilities were readable or writable by any
process running as the same user, and the elevated app acted on them. This
release closes every live finding, plus the documentation claims the
reviews falsified. No behavior you rely on changes — the fixes are all
about who gets to influence the elevated app, and what the docs admit.

## 1. The intercept journal can no longer be forged into elevated commands

An intercept session writes its undo record to
`%LOCALAPPDATA%\AutoCommand\intercept\session-active.json`. At every app
start, crash recovery replays that file into elevated `netsh` calls. The
directory was user-writable and the fields were unvalidated, so any
non-elevated process could write a journal that the app itself executed
with admin rights — `FirewallRules: ["all"]` deleted every firewall rule
on the machine at next launch, and a forged proxy "before" value pointed
every Windows service at an attacker host. Three locks now hold:

- **Validation at the sink.** Rule names must match the exact
  `AutoCommand Intercept QUIC block (pid)` shape the hooks themselves
  generate; proxy restores must be a real `host:port`; anything else
  degrades to the conservative action (reset / clear / skip). Forged
  content is now inert.
- **ArgumentList everywhere.** netsh arguments travel as structured
  process arguments — no caller string can break out into extra tokens.
- **The directory is admin-only.** The intercept folder (journal and CA
  key with it) is created Administrators/SYSTEM-only, so a non-elevated
  process cannot write the journal in the first place.

## 2. Sysmon64.exe is verified by digest, not by certificate

The previous signature gate read the signer certificate out of the
downloaded file and built its chain. That proves the *certificate* is
Microsoft's — not that the surrounding bytes are the file Microsoft
signed: a tampered Sysmon64.exe with an intact certificate table, or any
renamed Microsoft-signed binary, passed it and was executed elevated.
The gate is now a full `WinVerifyTrust` Authenticode verification —
digest over the current bytes plus signer chain, then the Microsoft
subject pin. Applied to the cache, every local source, the fresh
download, and user-supplied offline copies alike.

## 3. No more cleartext egress: RDAP-only IP attribution

Enriching unknown destination IPs used the free ip-api.com endpoint over
**plaintext HTTP** — every unclassified remote IP this machine connects
to was visible to anyone on the network path, from the very tool that
exists to notice exactly that. The ip-api step is removed; attribution
is RDAP-only (HTTPS, IANA-bootstrap routed, its own pacing, caching and
negative state). Labels keep their `· RDAP` provenance marker.
**PRIVACY.md** no longer claims "no other network sender anywhere in the
codebase" — it now spells out all three outbound lookups (RDAP, the
Sysmon download, the DBX blob) with what each sends and when.

## 4. The AI bridge tells the truth about what can mutate

The MCP `initialize` instructions hardcoded "the only mutating tools are
open_gate/close_gate" while the registry had grown to five (it also
includes `close_shieldsup_door`, `opt_out_telemetry` and
`apply_shieldsup_preset`). A model's picture of what can change the
machine is a safety input, so the sentence is now generated from the
registry itself — it cannot drift again.

## 5. Gates re-arm before their record is dropped

Closing an agent gate removed the gate record first and re-enabled the
blocks second, swallowing firewall-COM failures — a transient error left
the target unblocked with no record saying it should be blocked. Now the
re-arm happens first with three retries, and a final failure keeps the
expired gate on a 30-second retry tick (and re-arms at next startup).
The "door silently open" window is closed.

## 6. Lockdown snapshots before it deletes

*Restore defaults + lockdown* calls `RestoreLocalFirewallDefaults`, which
irreversibly deletes every non-default firewall rule on the machine —
other security software's, VPNs, Docker/WSL, your own. A full snapshot
of every rule (all fields) now lands under
`%PROGRAMDATA%\AutoCommand\firewall-snapshots\lockdown-<timestamp>.json`
before the reset runs, and the progress report names the file.

## 7. Preference files stop depending on how the app was launched

`sstp`/`kdnet` allow-lists, the privileged-task whitelist,
auto-mitigate and confirm-confirmation prefs were resolved against the
process's current working directory — a shortcut with a different
"Start in" (or the AgentProxy wake path) silently read and wrote a
*different file*, so settings appeared to forget themselves and
enforcement state depended on launch mechanics. All now resolve against
their data roots (`%PROGRAMDATA%\AutoCommand`, `%LOCALAPPDATA%\AutoCommand`)
with a one-time import of legacy copies.

## 8. Intercept hardening

- **Upstream TLS validation now checks revocation** — a
  confirmed-revoked upstream certificate fails the intercept leg
  instead of passing while your browser would have refused it.
  Revocation-unknown (offline OCSP) still soft-passes, browser-equivalent.
- **The WinHTTP bypass list survives sessions** — it used to be reset to
  `<local>` on every restore, discarding custom bypasses.
- **Minted leaf private keys are dropped when a session ends** instead
  of sitting in a static cache for the life of the process.

## 9. Documentation that survives an audit

- README: "It sends nothing anywhere" and "deleting the folder
  uninstalls it completely" rewritten to claims that hold (outbound
  lookups enumerated; the Sysmon driver / firewall rules / hosts pins
  footnote stated plainly).
- TECHNICAL_NOTES: the intercept-results row no longer claims decrypted
  bodies are "in memory until the user says so" — they persist to the
  transmissions archive on disk, and the row says where and for how long.
- SECURITY.md: the `SECURITY-EMAIL-NOT-YET-SET` placeholder (published
  against its own comment's instruction) is gone; GitHub private
  vulnerability reporting is stated as the channel.

---

**Verification:** Release + Debug build clean; all eleven offline
self-test suites pass (NetWatch 76, Contain 93, Harden 42, WSL 48,
StartupHealth 22, AllowList 24, OneSettings 43, PyTrace 21, Bridge 19,
ProxyInstall, Intercept — the latter's two machine-Root checks require
an elevated runner, as CI provides).
