# v2026.11.9 — trust your own folder again

## The theme

A full audit of this codebase found one repeating weakness: **the elevated app
trusted files that a non-elevated process can write.** AutoCommand runs as
administrator — its threat model is "untrusted code running as the user" — so
every one of these was a way for user-level code to get admin behavior. This
release closes all of them, removes the last telemetry code from the family
tree, and fixes the reliability bugs the same audit turned up.

## Security: closed privilege gaps

- **The Sysmon installer verified nothing.** The download cache lived in
  user-writable `%TEMP%` and was executed elevated with no checks: any
  same-user process could pre-plant a file at `%TEMP%\AutoCommand_Sysmon\Sysmon64.exe`
  and it would run with admin rights at the next install or repair. The cache
  is now trusted only when it is Microsoft-signed and plausibly sized;
  anything else is re-downloaded over HTTPS — and the download itself must
  verify or the install aborts.
- **OneDrive removal read HKCU.** The uninstaller path was resolved from a
  registry hive any user process can write (`HKCU\...\Uninstall\OneDriveSetup.exe\UninstallString`)
  and executed elevated. HKCU is no longer consulted; every candidate binary
  (registry or directory scan) must be named `OneDriveSetup.exe`/`OneDrive.exe`
  AND carry a valid Microsoft signature before this app runs it.
- **Desired-state files under ProgramData were user-writable.** A fresh
  folder there inherits "Authenticated Users: Modify", so a standard-user
  process could rewrite `firewall_baseline.json` / `firewall_config.json` /
  `bloatware_config.json` — and the 60-second drift enforcer would then
  disable/enable firewall rules on the attacker's behalf. The data root is
  now ACL-hardened (admins + SYSTEM full, users read-only), with inheritable
  rules so future files are covered too.
- **Inbox tools were resolved by bare name.** `netsh`, `bcdedit`, `powershell`,
  `wsl.exe`, `icacls.exe`, `sc.exe`, `wevtutil.exe`, `reg.exe`, `ipconfig` were
  launched unqualified from an app that ships as a portable folder — a planted
  `netsh.exe` next to the exe would run elevated (Windows searches the app
  directory and CWD before System32). Every launch is now pinned to
  `%SystemRoot%\System32`.
- **"Always for this session" grants could widen.** Confirming "open a
  1-minute block gate?" then authorized a 60-minute one for the same target,
  and a grant for one ShieldsUp door/preset silently covered the others.
  Grants are now keyed to the full argument shape: target AND duration for
  gates, target for doors/presets/rules.
- **The intercept CA's private key sat in plaintext.** The CA backing
  machine-wide TLS trust persisted as a password-less PFX in user-writable
  `%LOCALAPPDATA%`. It is now DPAPI-encrypted at rest (older plaintext files
  upgrade in place on first load).
- **The intercept teardown had two stranding windows.** A failure between
  trusting the CA and installing the hooks left the CA machine-trusted with
  no undo; and the undo journal was deleted even when the CA's removal
  failed. The journal is now written BEFORE the first system change, kept
  until the CA is confirmed out of the Root store, and a failure that lands
  in the unjournaled window un-trusts the CA explicitly. Teardown racing a
  new session no longer removes the CA the new session is using.
- **Telemetry opt-out rules could write anywhere.** A tampered rules file
  drove `Registry.LocalMachine.CreateSubKey(...)` with no constraints. Writes
  are now confined to a policy-key allow-list; JSON opt-outs to config-file
  locations. (The DNS probe already treated the file as untrusted; the
  mutation paths now match.)
- **The OneSettings watchdog registered SYSTEM tasks blindly.** A SYSTEM
  task pointing at `Environment.ProcessPath` means "replace the exe, own
  SYSTEM" when the app runs from Downloads. Registration now refuses
  user-writable locations with instructions to move the install.
- **The agent proxy trusted by name.** `AgentProxy` accepted a session whose
  pid ran any process named `AutoCommand*` — a same-named impostor with its
  own `session.json` could capture the assistant's data channel. It now also
  verifies the process image lives in the app's install folder. Stdin is
  pinned to UTF-8 (MCP-over-stdio is UTF-8; the console code page mangled
  non-ASCII tool arguments).

## Privacy: the old telemetry is gone — everywhere

The GA4/Firebase analytics code from the SystemMonitor era remained in the
archived `systemmonitor/` tree — with a live API secret committed. This
release removes the analytics service, its config files, its consent flow and
every call site from the archived tree (the EULA flow stays, re-keyed to a
local settings flag; its text now says plainly: no telemetry). The retired
GA4 credential appears in **other public repos in this family** (`myfirewall`,
`SystemMonitor`) and was removed there in the same sweep — **if you run any
of those, update them; and rotate/revoke that credential in your Google
Analytics admin regardless, since public history still contains it.**
AutoCommand itself has sent nothing but the opt-in anonymous daily count
(public code, `telemetry/`) and still sends nothing new.

## Reliability: the audit's "your own tool broke your PC" class

- **Re-enabling a service no longer demotes it.** "Re-enable" hardcoded
  `Manual`, so an Automatic service (RasMan — your VPN) silently stopped
  starting at boot after a disable/enable cycle. The pre-disable start type
  is recorded and restored exactly (both copies of the helper).
- **The kernel-debug check stops lying.** Detecting "debug ON" by finding the
  words `debug` and `yes` anywhere in `bcdedit` output matched
  `recoveryenabled Yes` + `debug No` on healthy machines — driving
  `bcdedit /debug off` every 30 seconds and a red alert every 60. The value
  of the loader's actual `debug` line is parsed now, in all three copies.
- **The security enforcer stops overlapping itself.** A callback slower than
  the 500 ms scheduling tick used to be re-dispatched while still running
  (a hung WMI call meant a new sweep every tick, forever). An in-flight
  guard skips re-dispatch; your Settings cadence choice also survives
  restarts instead of being force-re-enabled.
- **Process pipes stop deadlocking.** Every runner read stdout to EOF before
  touching stderr — a child that fills its stderr pipe (wsl.exe does;
  Sysinternals tools do) hung the elevated app forever, with no timeout.
  All runners now drain concurrently and kill at 120 s.
- **The block ledger can no longer be wiped by a locked file.** An
  unreadable `blocks.txt` (AV lock, share violation) was treated as "no
  blocks", and the next save rewrote the file with only new records. An
  unreadable store is now preserved as `blocks.txt.unreadable`, saves are
  atomic (temp + replace), and the legacy import no longer mistakes sibling
  directories for this install.
- **A gzip bomb can no longer OOM the app.** Decoding capped the compressed
  size but not the expansion — any HTTPS server could serve a 16 MB bomb
  that inflated to gigabytes inside the elevated process during a peek.
  Decoded output is now hard-capped at 64 MB; over-budget bodies show as
  compressed/flagged, like any undecodable body.
- **Update freezes survive a crash and a version change.** Freeze state was
  CWD-relative (orphaned by every version-folder change — the deny ACE then
  outlived the app's ability to undo it) and was saved only AFTER the deny
  was applied (a crash in between froze an exe with no state, so the app
  itself refused to thaw it). State now lives in an absolute path, is
  written before the deny, saves atomically, and adopts old CWD-era freezes
  at startup.
- **Shutdown cannot deadlock.** The exit path awaited gate-closing inline on
  the UI thread — a classic hang shape. It now runs on the thread pool with
  a 10 s ceiling (gates also self-expire and reconcile at startup).
- **UI fixes:** the Be My Guest tab no longer stacks a new 2-second refresh
  handler on every visit; the Blocks tab's traffic cache is thread-safe; the
  svchost CSV lives at an absolute path under `%LOCALAPPDATA%\AutoCommand`
  (no more files in System32), rotates at 5 MB, and keeps 7 days of rows;
  the blocked-rules window no longer pops a modal error every 15 seconds on
  a service hiccup, and its CSV export is properly quoted.
- **The privileged-task whitelist is honest.** The UI said "permanently";
  the set was memory-only and forgot itself every relaunch. It persists now.

## Honesty fixes

- **Geo labels now say what they are.** The org/country text on connection
  rows comes from a free geo-IP API that only serves plain-text HTTP —
  forgeable by anyone on the network path. Fresh labels carry a
  `· unverified` marker (RDAP-sourced labels, fetched over HTTPS, keep
  their clean name). Nothing about what the app sends changes.
- **Startup repairs what earlier crashes stranded** — this is the part you
  may actually see once:
  - an intercept CA still trusted machine-wide with no live session →
    removed (by thumbprint, and by exact subject for older installs);
  - the system or per-user proxy pointing at a dead `127.0.0.1:<port>` with
    nothing listening → reset.
  Each repair is shown in one dialog and appended to
  `%LOCALAPPDATA%\AutoCommand\startup-repair.jsonl`. No session that is
  actually running is ever touched.

## CI and hygiene

- `AllowListSelfTest` (the tamper-evident allow-list ledger — a security
  control with fully synthetic tests) now gates CI; it was missing from the
  strict list.
- `test-agent-bridge.ps1`'s negative checks actually assert now: the bad-token
  test used to send the *valid* token (PowerShell comma-call bound both
  values to one parameter) and the spoofed-Host check only printed — the
  bridge's 401/403 defenses were appearing tested while testing nothing.
- Repo: `evidence/`, `firebase_config.json`, runtime preference files are
  ignored; the machine-specific `ignored_processes.txt` is no longer tracked.

## Verification

- `dotnet build AutoCommand.csproj` Debug + Release — 0 errors.
- Strict suites run locally on this machine; full gate in CI (the temp-dir
  suites that cannot create directories inside this dev sandbox fail
  identically on the pre-change tree — environment, not code).

## Not in this release, on purpose

- **Ephemeral per-session CA.** DPAPI + journal-ahead + the startup sweep
  close the practical gaps; regenerating the CA per session is the deeper
  redesign and gets its own change.
- **Helper dedup across `Helpers/` and `ShieldsUp.Core/Helpers/`.** The
  drifted copies now carry the same fixes (each was patched in place), but
  one shared source is a structural follow-up.
