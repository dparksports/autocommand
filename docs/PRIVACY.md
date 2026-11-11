# AutoCommand privacy policy

**The short version: AutoCommand collects nothing about you and reports to
no one. Not at startup, not on a timer, not "anonymized."** The only
automatic outbound traffic is questions to *public directories* — when the
monitor sees an IP it cannot identify locally, it asks public RDAP
registries (over HTTPS) which organization owns that address. The registry
sees the queried IP and nothing else; no identifier, no behavior, no
payload of yours. The full list of outbound lookups is
[below](#network-lookups-spelled-out).

The only exception is a **voluntary, opt-in daily count**. If — and only if —
you clicked **"Yes, count me in"** in the dialog the app showed you once, the
app sends the following, at most once per day:

| Field | Value | Why |
|---|---|---|
| `a` | `"autocommand"` | Which app |
| `v` | Build date, compact (e.g. `261015`) | Day-level track of which builds people run |
| `o` | Windows build (e.g. `10.0.26300`) | Know which builds to support |

**There is no identifier in the count — not even a random one.** No
install id, no machine id, no account, nothing that could ever be connected
back to you, your PC, or your Windows account. Each consenting install adds
1 to a daily total, and the server stores daily totals and nothing else:
no per-user rows exist anywhere in the system.

**What this count is not:** no hostnames, no process names, no connection
data, no behavioral events, and nothing about anything you do inside the app.

**Your IP address is never read, stored, or forwarded by AutoCommand's
counting code.** The receiving server (a Cloudflare Worker; code public in
this repository under `telemetry/`) learns only the country code Cloudflare
itself derives at the network edge, and increments a counter. Its entire
database is daily totals per (app, version, country) — a leak of it reveals
counts, and nothing else. The spec, worker code, and schema are public in the
repository's `telemetry/` folder: verify, don't trust.

**Changing your mind:** delete the registry key
`HKEY_CURRENT_USER\Software\AutoCommand\UsagePing` (or set its `Consent`
value to `no`). That withdraws consent permanently. Uninstalling the app
removes the settings with it.

**Everything else the app stores** stays on your machine, in readable files
listed in the [Technical Notes](TECHNICAL_NOTES.md).

**Network lookups, spelled out.** Three features reach the internet, each
sending only what that feature needs:

- **IP ownership (automatic, HTTPS only):** destination IPs the local
  classifier cannot identify are looked up at public RDAP registries
  (IANA-routed, e.g. rdap.org) so rows can say "Akamai" or "Gcore" instead
  of a bare address. The registry learns the queried IP; that is the entire
  payload. (An earlier build also used the free HTTP endpoint of
  ip-api.com — that cleartext sender has been removed.)
- **Sysmon install (only when you click Install):** Sysmon64.exe downloads
  from live.sysinternals.com over HTTPS and must pass a full Microsoft
  Authenticode verification (digest + signer chain) before it is ever run.
- **Secure-boot DBX remediation (only from the Shields Up tab):** the
  revocation-list blob downloads from Microsoft's
  `secureboot_objects` repository on raw.githubusercontent.com over HTTPS.

No lookup carries an identifier, and no feature sends any captured content
(bodies, keys, hostnames, process names) anywhere.

**BITS Transfers tab, spelled out.** It watches what Windows itself records
about Background Intelligent Transfer jobs (the Bits-Client event log and the
read-only COM queue) and stores that metadata locally. Two things it does
touch go one step further, so the rules are explicit:

- **Delivered files are hashed (size + SHA-256) automatically** when a job
  completes — the same class of local-only metadata Sysmon produces for every
  binary. No file bytes are kept.
- **File *content* is shown only when you click "Preview content"** on a
  specific file — one explicit action per file, rendered in a read-only
  window, in memory only. Content is never written to disk, never included in
  any export, and never sent anywhere.

Everything the tab persists (`%LOCALAPPDATA%\AutoCommand\bits\`) is job
metadata only, in the readable files the Technical Notes list.

Contact: SECURITY.md lists how to reach the maintainer.

© 2026 Dan Park, magicpoint.ai
