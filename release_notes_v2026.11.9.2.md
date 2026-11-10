# v2026.11.9.2 — Sysmon without internet

## The problem

AutoCommand itself never needed internet: the zip is self-contained,
everything it records stays on the machine, and the optional
enrichments degrade gracefully when there's no network. But **Sysmon**
— required for the Spawns timeline and network attribution — had
exactly one source: a download from live.sysinternals.com. On an
offline PC (a field report from a brand-new, air-gapped Windows 11
box) the install failed with a raw socket error, and the follow-up
"install fails, then repair" dance was confusing rather than helpful.

## What changed

**The installer now resolves Sysmon64.exe offline-first**, each source
behind the same Microsoft-signature gate as the download itself:

1. the verified `%TEMP%` cache (as before)
2. **a user-supplied `Sysmon64.exe`** placed next to `AutoCommand.exe`
   or in its `tools` folder — the documented air-gapped path
3. **the deployed binary** a previous install left in `C:\Windows` —
   which also lets an inconsistent install repair itself with no
   download at all
4. the HTTPS download — last resort, not the only path

When the download is the failure, the error is now an actionable
plain-English message instead of a socket error, and the setup flow
offers **"use a local copy"**: pick a Microsoft-signed Sysmon64.exe
(OpenFileDialog), it is verified and seeded into the cache, and the
install retries immediately.

## Why Sysmon is not bundled with the app

Microsoft's current Sysinternals license terms do not permit shipping
the binary inside another product ("You may not … publish the software
for others to copy … transfer the software … to any third party"). So
the offline path is bring-your-own-copy: on any connected PC download
`Sysmon64.exe` from [live.sysinternals.com](https://live.sysinternals.com/Sysmon64.exe),
move it to the offline machine (USB), and drop it next to
`AutoCommand.exe` — or answer Yes to "use a local copy". Installing
and using it on your own devices is exactly the right the license
grants you. The README now has an **"Offline (air-gapped) PCs"**
section spelling this out, and the signature gate (introduced in
v2026.11.9) is what makes a user-supplied copy safe to consume: a
local copy is acceptable exactly when it verifies as Microsoft-signed.

## For the field-report machine

If that box also showed "install fails → repair fixes it": the
deployed-binary source (#3) plus the repair flow means an offline
machine with any previous Sysmon state now converges on its own —
repair no longer needs a download. On a clean offline box, place the
USB-brought `Sysmon64.exe` beside the app exe once and both install
and repair work forever after.

## Verification

- `dotnet build` Debug + Release — 0 errors.
- Strict CI gate green on the change commit (run 42763836665).
- Download+signature chain spot-checked live: 3.1 MB, Authenticode
  Valid, `CN=Microsoft Windows Publisher, O=Microsoft Corporation` —
  the gate accepts the genuine artifact and refuses anything else.
