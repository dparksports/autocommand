# v2026.11.10.6 — Encrypted at rest, de-elevated watch, honest scopes

The follow-up to v2026.11.10.5's trust-door release: the same reviews'
remaining items, in the same spirit — what the docs promise matches
what the code does, and the elevated app keeps shrinking how much
user-session input reaches it.

## 1. Decrypted bodies are now encrypted at rest

The Transmissions archive persisted decrypted request/response bodies
(cookies, bearer tokens, POST credentials) as plaintext files under
`%LOCALAPPDATA%\AutoCommand\transmissions\bodies\` — while the far less
sensitive TLS keylog always had explicit ACL hygiene. Now every body
blob is written as a **DPAPI (current-user) encrypted** file, and the
bodies directory is created **current-user-only** with inheritable
rules. The metadata index stays plaintext and greppable; each row's
SHA-256 still hashes the plaintext, so "what was sent" remains provable
after the fact. The viewer decrypts transparently, and pre-encryption
legacy blobs still load.

## 2. Launch-under-watch children no longer inherit admin

AutoCommand runs elevated, and users casually pick *browsers* to watch —
until now those children inherited the full administrator token, quietly
eroding the UAC boundary for every renderer exploit. The watched program
now starts via a **LUA-filtered copy** of this process's token
(`CreateRestrictedToken` + `CreateProcessWithTokenW`): admin group
filtered, medium integrity. The only thing it needs from AutoCommand —
the `SSLKEYLOGFILE` variable — travels in an explicit environment block,
so the launch flow behaves exactly as before.

## 3. The intercept consent dialog states the real scope

The dialog said "only the target PID is decrypted" while the engine
decrypts every process running the same image path (that matching is
deliberate — browsers spawn new PIDs per tab, and firewall rules cannot
distinguish PIDs; shared hosts like svchost stay PID-exact). The
consent dialog now says plainly: **"every process running from this
exe, not just PID n"** — the same honesty the gate tool descriptions
always had. Class docstring and TECHNICAL_NOTES updated to match.

## 4. Be My Guest consent: fixed drift + a plain boundary note

The session-start dialog still claimed "the only mutating actions are
block gates" — the exact drift the bridge instructions had (there are
five mutating tools; the v2026.11.10.5 release fixed the instructions,
this fixes the human-facing dialog). It also now states the boundary in
one line: **anything running as your user can read what the AI reads** —
the session token lives in a local file while the session runs.

## 5. CI: pinned actions + dependency-vulnerability gate

`actions/checkout` and `actions/setup-dotnet` are pinned to **verified
full commit SHAs** (a floating `@v4` tag executes whatever it points at
tomorrow, with this workflow's permissions — including `contents:write`
on the release path). A new CI step runs
`dotnet list package --vulnerable --include-transitive` and fails the
build on findings — the online enforcement that complements the
NU1900 offline suppression.

## 6. Lockdown is now reversible: snapshot restore

v2026.11.10.5 made every Shields Up lockdown photograph the firewall
before `RestoreLocalFirewallDefaults` irreversibly deleted the rules.
This release completes the loop: a **⏪ Restore snapshot…** button in
the Firewall tab re-imports a snapshot — rules the reset deleted are
recreated from every photographed field, surviving default rules are
re-enabled to their photographed state, and rules created after the
snapshot are left untouched. The restore follows the profile-apply
contract exactly: drift enforcer paused for the transition, end state
re-captured as the enforced baseline.

## 7. Uninstall-day removal primitives

Three new engine capabilities, ready for the "remove everything"
flow (the wizard UI ships next release; the primitives are here and
suite-covered):

- **`SysmonInstallerService.UninstallAsync()`** — the public Sysmon
  removal entry (stops/removes the Sysmon64 service and driver, cleans
  the event-manifest registration and the deployed exe). This path
  existed only inside the repair flow and had no caller.
- **`FirewallService.RemoveAllOwnRulesAsync()`** — *deletes* (the panic
  button only disables) every rule this app ever created: current
  AC-BLOCK prefixes, legacy names, and intercept QUIC blocks. Own
  prefixes only; Windows and third-party rules are never matched.
- **`HostsTelemetryPins.RemoveFromLiveHosts()`** — removes every marked
  telemetry pin block with the same never-touch-user-lines contract as
  the rest of the class, backing the file up first.

## 8. Dead code and local hygiene

The bridge's never-wired `FeedLoop`/`StartFeed` pair is gone
(`feed.jsonl` keeps its session-start snapshot; live state comes from
`BuildMonitorSnapshot` on demand).

---

**Verification:** Release + Debug build clean; all eleven offline
self-test suites pass on the release machine (NetWatch 76, Contain 93,
Harden 42, WSL 48, StartupHealth 22, AllowList 24, OneSettings 43,
PyTrace 21, Bridge 19, ProxyInstall — Intercept 11/13 locally; its two
machine-Root checks pass on CI's elevated runner, where this exact
commit's suite run is green).
