# AutoCommand — Technical Notes

How AutoCommand delivers what the [README](../README.md) promises: the technologies behind each capability, the design rules they follow, and every place on disk the app writes. No marketing — just what runs, what it touches, and why.

> **Note (v2026.10.22):** the consumer tabs (Quick Scan, Attack Surface, Bloatware, Telemetry, Privacy, Update Control, Tasks, Startup, Hibernation, OS Hardening, DBX Safety) moved to [Shields Up](https://github.com/dparksports/shields-up/releases/latest) and were removed from the UI. Sections below that describe those features cover services that remain in the codebase but currently have no tab in the app.

---

## Design rules

1. **Zero-PowerShell core.** Monitoring and mitigation talk to Windows directly — COM, WMI, and P/Invoke — never by spawning `powershell.exe`. Native command-line tools (`powercfg`, `bcdedit`, `schtasks`, `wevtutil`) are used only where Microsoft ships no COM or .NET surface, and always through one audited runner (`Helpers/ProcessRunner.cs`).
   *The one documented exception:* applying DBX updates uses the `Set-SecureBootUEFI` PowerShell cmdlet, because Microsoft provides no native C# API for UEFI Secure Boot variable writes.
2. **Nothing runs without you.** Bloatware removal, firewall profile applies, and DBX updates all confirm first.
3. **Non-removable means non-offered.** System-signed OS components are filtered out of the Default Apps list and are never offered by bloatware removal — by design, not by configuration.
4. **Verified downloads.** Auto-downloaded tools (Sysinternals `sigcheck64.exe`) must pass both a logged SHA256 check and a native `WinVerifyTrust` Authenticode verification; anything else is deleted, never executed.
5. **Plain, inspectable state.** User preferences live in readable JSON and text files (listed at the end), so you can back up, diff, or edit everything the app remembers.

---

## Subsystem by subsystem

### Process Monitor & network analytics
| Concern | Technology |
|---|---|
| Connection events | Sysmon — `EventLogWatcher` over the `Microsoft-Windows-Sysmon/Operational` channel; the installer configures the manifest via `wevtutil` and can repair inconsistent installs |
| Packet counters | Raw-socket sniffer — `IOControlCode.ReceiveAll` (SIO_RCVALL) on raw IP sockets, one IPv4 plus a best-effort IPv6 socket; no WinPcap/Npcap dependency |
| Name resolution | Background reverse-DNS + org-label service — see **DNS & org resolution** below |
| Task attribution | taskhostw instance GUID on the command line correlated with Task Scheduler history (the channel is enabled once if off); COM-handler tasks get their ClassId resolved through `HKCR\CLSID\{…}\InprocServer32` to the handler DLL, flagged when unregistered |
| Live ordering | WPF `ICollectionView` live sorting on the row's `LastSeen` timestamp; stale rows detected off a UI timer |
| TX-only filter | Off-by-default view lens: `ICollectionView.Filter` + live filtering over a time-gated `IsTxOnly` flag (sent bytes > 0, received = 0, row ≥ 30 s old — the grace keeps mid-handshake rows from flashing, since rows seed at 0/0 and Rx only lands when a reply crosses the sniffer); the checkbox label carries the live count while the lens is off; a view lens only — ingestion, the CSV export and the AI-audit context all read the unfiltered source |
| Row lifecycle | `LastSeen` seeded from the Sysmon event's UTC time (one-shot connections still get a real timestamp); the UI timer marks rows "— exited" once their PID is gone, and a later Sysmon event re-attributes the row to a new PID on the same remote IP |
| Traffic Peek | Right-click → **Peer into this connection / this program** or **Track this service** opens a subject-scoped window (see below) |

### Traffic Peek ("Peer into this connection")

A subject-scoped inspection window from the Process Monitor context menu, powered by a
`FlowPeekService` in `Engines.Watch`:

| Concern | Technology |
|---|---|
| Capture lifetime | The shared `TcpStreamCaptureService` (raw socket, SIO_RCVALL) runs **only while a peek window is open** — the peek is the sole `AddRef`/`Release` holder, so idle AutoCommand captures nothing; nothing is persisted (flow persistence stays off) |
| Flow finalization | The peek shortens the capture's idle sweep to 10 s while open (restored on close), so long-lived conversations surface without waiting for them to close; RST/FIN-closed flows appear immediately |
| Scopes | Three subjects, one engine: **remote IP** (`RemoteIpScope` — "this connection"), **program instance** (`ProgramScope` — PID-anchored via EID 3, with image-equality fallback that is refused for shared hosts), and **service name** (`ServiceScope` — each connecting PID's hosted services are resolved over WMI with a 30 s TTL, so a pinned service keeps being tracked across restarts where a PID pin would go stale) |
| PID attribution | Its own `SysmonConnectWatcherService` (Sysmon EID 3) feeds `TagFlow` — first-writer-wins, so a future Transmissions pipeline doing the same is harmless; Sysmon absent degrades to a note, never a failure. Program/service scopes say so in the status strip: without Sysmon they stay empty |
| Track this service | Right-click a svchost row → **Track this service** opens a service-scoped peek: it follows whichever svchost instance hosts the pinned service next (DiagTrack, CryptSvc…), with no user action on respawn — the scope is the NAME, not the PID |
| Launch under watch | **🚀 Launch under watch…** (`TransmissionKeyService`, recreated from autocommand-ii) starts one program with `SSLKEYLOGFILE` set in *its* environment only and opens a program-scoped peek for the new PID — its flows decrypt as they finalize. The system-wide capture (HKCU\Environment + broadcast) ships in the same service |
| TLS metadata | Always extracted from the ClientHello (SNI, ALPN, cipher, TLS version) — keys or no keys |
| Plaintext | Only when session keys exist in the keylog (`%LOCALAPPDATA%\AutoCommand\pytrace\sslkeys.log` — opt-out flag file honored: the peek never recreates a keylog the user disabled). **schannel services (wuauserv, BITS, DoSvc) never log keys** — their rows stay metadata-only and the window shows the decryptor's verbatim reason instead of pretending |
| Coverage note | On every "encrypted (no keys)" row the window shows which apps honor SSLKEYLOGFILE and states plainly that schannel components never will — the honest coverage answer, not a gap |
| Python instrumentation | **🐍 Instrument…** (any peek window) opens the per-environment opt-in dialog: the audit hook (`PyTraceHook_ac.py` + `.pth`, embedded in `AutoCommand.Forensics.Core` and read from that same assembly) lands in discovered environments' site-packages. Instrumented pythons report spawn call stacks (`trace-<pid>.jsonl`) and TLS session keys — a program-scoped peek of a python process shows the "Python audit trace" section for exactly that pid |
| Intercept (layer 3) | On a "encrypted (no keys)" flow in a program/service scope: **🛡 Intercept this process…** — a time-boxed (15 min) local TLS-terminating proxy (`InterceptProxyService` in the recreated `AutoCommand.Intercept.Core`). The session installs the loopback proxy as the temporary WinHTTP (services) + WinINET (apps) proxy via `InterceptSystemHooks`, blocks the target's UDP/443 so QUIC falls back to TCP, and MITMs only connections the kernel TCP table attributes to the target PID — everything else is tunnelled untouched. Only the PID matches; image matching is refused for shared hosts, so a svchost target is always exactly one service tenant |
| Intercept trust & teardown | A per-install CA (`CN=AutoCommand Intercept CA`, RSA-2048, `%LOCALAPPDATA%\AutoCommand\intercept\ca.pfx`) is trusted into the MACHINE Root store only while a session runs and removed by thumbprint at session end. Every hook change is journaled to `session-active.json`; `RecoverAfterCrash()` runs at app start and undoes whatever the journal still describes. An UNREADABLE journal is left in place, never guessed at (a partial write may be the only undo record). The app exit path stops any live session. Certificate-pinned clients fail loudly — recorded as "refused intercept (pinning)", a signal, not an error |
| Intercept results | Decrypted conversations flow through the pipeline's `IngestIntercepted` seam into the scoped peek that started the session: rows tagged "decrypted · intercept" with request/response bodies viewable in-place (text + hex) and exportable with 💾 Save bodies — in memory until the user says so |
| Service activity | The Windows Update / BITS / Delivery Optimization operational channels read for the flows' time window — the plaintext "what did this service actually do" that TLS metadata cannot show; missing channels (DO on some SKUs) contribute nothing |
| Scope guard | Only flows belonging to the subject are processed; one window per subject ("ip:x" · "pid:N" · "svc:name" — a second Peer on the same subject focuses the existing window) |
| Where data goes | Nowhere. Capture, decryption and event reads are local; the only network I/O is the connection being observed itself |

### DNS & org resolution (the Host column)

| Concern | Technology |
|---|---|
| Hostnames | Reverse DNS with a persistent cache (24 h TTL); Sysmon-provided names are seeded directly |
| Org/geo labels | Cached **per /24 prefix** (14 d positive, 24 h negative) so one answer covers a whole rotating fleet block. Source cascade, cheapest first: in-app range classifier → non-routable ranges (answered, no lookup at all) → prefix cache → ip-api.com (throttled at the free tier's 45 req/min, backoff doubling to 5 min on 429/timeouts and resetting on success) → **RDAP registry fallback** (the same IANA-bootstrap-routed engine the Blocked tab uses — its own cache, its own pacing, zero cost to the ip-api budget) |
| Transient failures | Cache nothing — a wrong "unresolved" must not outlive the outage; once the backoff window clears, a later pass retries |
| Why an IP shows no name | Every Host cell carries the reason in its tooltip: local-by-design, resolving (with queue depth), throttled (with a retry estimate), negative-cached (with the retry time), or resolved (with when) |
| User control | Right-click → **Resolve now** (user-initiated: skips the inter-call spacing for that one lookup; cooldowns still apply), **⟳ Retry unresolved DNS** (forgets negative answers and raw-IP placeholders, resets the backoff, re-queues the view's unresolved rows at normal pacing), and the **idle reconciler** (see next row) |
| Idle reconciliation | Every placeholder answer is already persisted in the hostname cache, so "all unresolved IPs" falls out of it oldest-first. When the Sysmon feed has been quiet for 5 minutes (traffic idle — re-checked every minute), batches of 8 addresses are re-asked through the normal paced pipeline; 2-minute cooldown between batches; 5 attempts per address per session, then left until the entries age out (24 h). Fresh negative answers are never re-asked early. Wired to the watcher's `QuietFor` in the app; never runs in headless faces |
| Cache files | `C:\ProgramData\AutoCommand\dns_cache.json`, `geo_prefix_cache.json`, `dns_forward_cache.json` — machine-wide, so they survive install-folder moves (a legacy beside-the-exe cache is copied once on first run) |
| AI access | `lookup_ip` on the bridge reports the same cascade and state; `force: true` is the urgent path |

### Sysmon Audit
| Concern | Technology |
|---|---|
| Status facts | Service state via `sc query`, event-channel health and 24 h event counts via `wevtutil`/`Get-WinEvent`, active config hash from `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters` |
| Recommended config | Generated `sysmon_config.xml` capturing process creations (ID 1), network connections (ID 3) and DNS queries (ID 22); applied with `Sysmon64 -c` on existing installs |
| Install/repair | Download from `live.sysinternals.com`, `Sysmon64 -i -accepteula`; inconsistent-state repair removes stale manifest registrations (reboot + auto-retry when Windows holds the registration) |
| Process-creation feed | `EventLogWatcher` over `*[System[(EventID=1)]]` plus a time-bounded historical backfill reader |

### Update Control
| Concern | Technology |
|---|---|
| Discovery | Self-update `.old` leftovers, `*updat*` folders under the user profile, and "update" autostart Run keys; vendor shown via Authenticode signature |
| Freeze | ACL snapshot with `icacls /save`, then deny ACE `(DE,WD,AD)` for the current user on the exe, then verification that the deny is present; Windows-signed/system-path binaries refused |
| Thaw | `icacls /restore` of the snapshot; deny-ACE absence verified before state cleanup |
| State | `update_freeze.json` next to the exe; ACL backups under `freeze_backups\` |

### OneSettings cadence (🔄 tab + `OneSettingsCadence` CLI)

The 🔄 **OneSettings tab** and the standalone `OneSettingsCadence` CLI are two
faces over one engine (`OneSettingsCadence/OneSettingsCadence.Core`, linked
in-process by the app the same way `SvchostAnalyzer.Core` is — the CLI keeps
its own `Main()` and builds separately). It slows the Windows inbox task
`\Microsoft\Windows\Flighting\OneSettings\RefreshCache` — the OneSettings
remote-config fetch that runs ~20-40×/day as SYSTEM off a ~3h20m repetition
(+1h random delay, +WNF state-change triggers) — to a user-chosen interval, and
restores stock behavior afterwards. Task Scheduler is reached over the
`Schedule.Service` COM interface (same dynamic-COM pattern as
`Services/TaskSchedulerService.cs`), never through `schtasks.exe`. The app
manifest already demands administrator, so the tab applies changes with no UAC
round-trip; the CLI self-elevates.

| Concern | Technology |
|---|---|
| `status` / `preview` / `runs` | Read-only, no elevation (the task's security descriptor grants Authenticated Users read). `preview` runs the exact transform `set` would apply and prints the resulting task XML; `runs` (also the tab's third card) reads the Task Scheduler operational channel and compares observed launches against the expected cadence — each launch bucketed by why the scheduler says it fired (timer / event / logon / manual-API). WNF state-change triggers fire through the same EID-107 channel as the timer, so the verdict is WNF-aware: excess 107s with WNF triggers installed are theirs, not a reverted cadence |
| `set` | Self-elevates via UAC (the elevated child tees its output back to the caller's console through a temp file); writes a timestamped backup of the live XML under `C:\ProgramData\AutoCommand\onesettings-cadence\backups\` (UTF-16, round-trip-verified), re-registers, then re-reads the live task and compares interval / random delay / WNF trigger count — any mismatch rolls back from the backup (a failed rollback exits 4 and says so loudly) |
| The transform | Touches `Triggers` only: repetition interval set, `RandomDelay` forced to `PT0S`, `WnfStateChangeTrigger` elements removed unless `--keep-wnf`. A repetition `Duration` shorter than the new interval is dropped (absent = indefinite) so the pattern cannot re-arm on the boundary. Principal (S-1-5-18), actions, settings and `SecurityDescriptor` are preserved from the live XML |
| Watchdog | Optional (`set --watchdog`, or the tab's checkbox): a SYSTEM task `\AutoCommand\OneSettingsCadenceWatchdog` (daily 03:30 + logon) re-applies the saved cadence only when the live task drifted — Windows servicing rewrites inbox task definitions (this machine's `StartBoundary` was rewritten by the OS the day the tool was written). From the CLI the watchdog runs the exe with `enforce --quiet`; from the tab it launches AutoCommand.exe with the `onesettings-enforce` argument, handled headlessly in `App.OnStartup` before any window loads. `restore` removes the watchdog so it cannot fight the restored stock definition |
| `restore` | Re-registers the newest backup (or `--backup <file>`), with the same snapshot → register → verify → roll-back discipline; clears the saved cadence and removes the watchdog on success |
| Interval input | Plain hours (`24`, `24h`, `0.5`), clock (`06:00:00`, `6:00`), or ISO 8601 (`PT24H`, `P1DT12H`); default 24h; warns below 6h or above 72h (cached OneSettings payloads declare ~72h freshness windows) but proceeds |
| Audit | Every change (what, when, old→new interval/delay/WNF count, backup filename, user, result) is one JSONL line in `onesettings-cadence\audit.jsonl` |
| Exit codes | `0` ok · `1` usage/task-not-found/IO · `2` drift found (`status`) or verified failure rolled back · `3` elevation declined · `4` rollback failed too |

Pure logic (parser, transform, drift detection, run-history field parsing and
compliance bucketing — including the exact-match event namespace a typo once
silently broke) has an offline self-test: `OneSettingsCadenceSelfTest`
(43 checks, no COM, no writes, no elevation).

| Live external starts | While the tab is open, an `EventLogWatcher` over the scheduler channel flags launches that fired with no trigger event (100 without 107/108/119 — something called `Run()`), confirmed on a 3 s deadline so out-of-order trigger events do not false-alarm; EID 129 supplies the taskhostw PID, Sysmon EID 3/5 join the fetch destinations and exit (pure correlator unit-covered; degrades to starts-without-evidence when Sysmon is absent) |

What the tab cannot enforce, honestly stated in the card itself: the watchdog
re-asserts the task *definition*; launches started by other actors (`Run()` on
the task) are counted and named but not preventable, and a component that
bypasses the task entirely (fetching OneSettings in-process from a service) is
invisible to scheduler history — it would surface as svchost traffic in the
Process Monitor, where it can be blocked like any other destination.

### Telemetry Opt-Out
| Concern | Technology |
|---|---|
| Knowledge base | `Assets\telemetry_rules.json` (detection, state probe, opt-out, revert per app); built-in seed fallback |
| Probes/appliers | JSON key read/write, user environment variables, HKLM policy values (DWORD or string) |
| Reversibility | Previous value snapshotted to `telemetry_state.json` before each change; Revert restores it (or deletes an added value) |
| Verification | `Get-DnsClientCache` checked for each app's known telemetry domains |

### Advanced Firewall
| Concern | Technology |
|---|---|
| Rule engine | `INetFwPolicy2` COM (`HNetCfg.FwPolicy2`) — enumerate, enable/disable, create block rules |
| Group names | Indirect strings (`@FirewallAPI.dll,-32752`) resolved via `SHLoadIndirectString` (`shlwapi.dll`) |
| Profiles & drift | Baseline of every rule's enabled state stored as JSON in `C:\ProgramData\AutoCommand`; re-scanned to report drift |
| 1-click blocks | Inbound + outbound rules per executable or remote address, created over the same COM interface |

### Security Enforcer
| Concern | Technology |
|---|---|
| Device events | WMI `__InstanceCreationEvent` / `__InstanceDeletionEvent` / `__InstanceModificationEvent` subscriptions on `Win32_NetworkAdapter` — zero polling idle cost |
| SSTP guard | Service state via the Service Controller; re-asserts stopped + disabled (`Start=4`) in a reconciliation sweep |
| Kernel-debug block | `bcdedit` state reads/writes plus KDNIC adapter removal |
| Adapter removal | `SetupAPI` P/Invoke (`setupapi.dll`) in `WanMiniportRemover.cs` — kernel-mode clean device removal, no `pnputil` |
| Logon task | `schtasks /create … /rl highest` via the shared runner |
| Alerts | Windows toast notifications (`Windows.UI.Notifications`) |

### Default Apps & Bloatware
| Concern | Technology |
|---|---|
| App inventory | `Windows.Management.Deployment.PackageManager` (`FindPackagesForUser`) — frameworks, resource packages, and System-signed components filtered to match Settings → Installed apps |
| Signature status | `Package.SignatureKind`, validated by the deployment engine at install time (Store / Enterprise / System / Developer / Unsigned) |
| Uninstall | `PackageManager.RemovePackageAsync` per package full name |
| OneDrive (Win32) | Not a Store package — detected via install directory + `UninstallString` registry entry (HKCU/HKLM), removed with `OneDriveSetup.exe /uninstall`, `winget` fallback |
| Your custom list | Delta config (opt-outs + additions) in `C:\ProgramData\AutoCommand\bloatware_config.json`, merged over the compiled-in defaults by `BloatwareConfig` |

### UEFI & Secure Boot
| Concern | Technology |
|---|---|
| EFI baseline | SHA256 hash of every `.efi` module on the EFI System Partition; drift reported against a stored baseline |
| Boot manager check | Sysinternals `sigcheck64.exe` — downloaded only after SHA256 + Authenticode (`wintrust.dll` `WinVerifyTrust`) gates; its UTF-16LE redirected output is decoded before parsing |
| DBX updates | `DBXUpdate.bin` downloaded from Microsoft's secureboot_objects repository, `EFI_SIGNATURE_LIST` parsed in C#, applied with `Set-SecureBootUEFI` after explicit confirmation |

### AI Assistant

> Removed in v2026.10.12 — the audit/insight feature is being rethought. The per-tab state serialization it used (`IAiAuditable.GetAuditContext()` in every view) is intentionally kept in the codebase as the foundation for whatever replaces it.

### Platform
* **.NET 10 (WPF)** front end.
* **README infographics** are generated by `Assets/generate_infographics.py` (Python + matplotlib).

---

## What the app writes on your disk

| Path | Purpose |
|---|---|
| `C:\ProgramData\AutoCommand\bloatware_config.json` | Your bloatware-list customizations (delta over defaults) |
| `C:\ProgramData\AutoCommand\firewall_config.json` | Per-rule firewall overrides |
| `C:\ProgramData\AutoCommand\firewall_baseline.json` | Firewall drift baseline |
| `C:\ProgramData\AutoCommand\onesettings-cadence\state.json` | OneSettingsCadence CLI — saved desired cadence for the inbox RefreshCache task |
| `C:\ProgramData\AutoCommand\onesettings-cadence\backups\RefreshCache-*.xml` | OneSettingsCadence CLI — timestamped task-XML backups (`restore` re-registers these) |
| `C:\ProgramData\AutoCommand\onesettings-cadence\audit.jsonl` | OneSettingsCadence CLI — audit trail: every change with old→new values and the backup filename |
| `<app>\blocked.txt` | Firewall blocks created from the monitors |
| `<app>\ignored_processes.txt` | Process Monitor ignore list |
| `<app>\ultimate_autopilot_stats.csv` | Hourly connection-stats export |
| `<app>\check_interval.txt` | Security Enforcer cadence |
| `<app>\update_freeze.json` + `freeze_backups\` | Frozen self-updaters and their ACL snapshots |
| `<app>\telemetry_state.json` | Snapshots of the settings changed by telemetry opt-outs |
| `C:\ProgramData\AutoCommand\dns_cache.json` + `geo_prefix_cache.json` + `dns_forward_cache.json` | Hostname, org-prefix and forward-DNS caches (machine-wide; a legacy beside-the-exe copy is migrated on first run). Forward cache: 60 min TTL, 10 min negative TTL |
| `%LOCALAPPDATA%\AutoCommand\pytrace\` | Python Spawns tab state — see below |
| `%LOCALAPPDATA%\AutoCommand\bits\` | BITS Transfers tab state — see below |

### BITS Transfers tab (`%LOCALAPPDATA%\AutoCommand\bits\`)

| File | Purpose |
|---|---|
| `jobs.jsonl` | One line per completed BITS job, appended at completion: full metadata (job GUID, creator process + PID, owner account, direction, URL/host/port, resolved IPs, destination owner org, bytes, status, verdict, reason, per-file remote/local names + size + SHA-256). Never file content. |
| `bits-stats.json` | Per-(creator → host) transfer rollups (counts, upload counts, per-day buckets, first/last seen); flushed at most once a minute when dirty |

Both are plain, readable files. The tab reads Windows' own `Microsoft-Windows-Bits-Client/Operational` event log and enumerates the BITS COM queue read-only (all users, via the elevation the app already has); it never creates, cancels or modifies jobs. File content is read only by the explicit per-file preview window, in memory, and never written anywhere.

### Python Spawns tab (`%LOCALAPPDATA%\AutoCommand\pytrace\`)

| File | Purpose |
|---|---|
| `trace-<pid>.jsonl` | Audit-hook records from instrumented pythons (written by the hook, tailed + cleaned up by the app) |
| `sslkeys.log` (+ `.old` while rotating) | TLS session keys written by instrumented pythons via `SSLKEYLOGFILE`; created with a current-user-only ACL, rotated at 5 MB, `.old` deleted at app exit |
| `no-keylog` | Flag file: the "Disable TLS keylogging" toggle — its presence makes the hook stop setting `SSLKEYLOGFILE` |
| `instrumented.json` | Manifest of python environments the audit hook was installed into (and the exact files written) |
| `env_scan.json` | Instrumentation discovery state: user-added scan roots, environments deliberately forgotten, last deep-scan time |
| `settings.json` | Tab settings (keylog toggle state, flow persistence, flow caps) |
| `flows\*.jsonl` | Optional persisted TCP flows (base64 payloads, off by default, rotated by budget) |

Outside that directory the tab only **reads**: the Sysmon operational channel (EID 1/5/3) and raw packets from the NIC on its own socket. The instrumentation itself is opt-in per python environment: two small files (`PyTraceHook_ac.py` + `.pth`) written into that environment's site-packages, tracked in the manifest, removable from the Instrument dialog. Nothing inside a venv is ever read for correlation; the interpreter binary is never touched.

### Why is this site slow? (🩺 tab)

Born from a real diagnosis (a site whose refreshes stalled for seconds): the archive said "zero server bytes everywhere," which was almost misread as "replies are blocked" until a control disproved it. The tab automates the corrected method — three engines, verdicts that never outrun their evidence.

* **`SiteFingerprintService`** — passive: groups the Transmissions archive by SNI and reads edge dispersion (4+ server addresses where this machine's own median is 1–2), 5-second connection bursts (browser racing retries), and single-edge churn. Signals are evidence lines, never conclusions; the archive only keeps >10 KB or decrypted conversations, so counts are a sample.
* **`SiteProbeService`** — active, hard-capped in code (~21 operations): 5 DNS resolves of the same name (rotation = short-TTL steering), per-edge TCP timing plus **two TLS hello shapes** (Windows-default vs plain TLS 1.2-only — a server that answers one and drops the other is the "works in one app, hangs in another" signature), and control-host handshakes so "your line is fine" is measured. Every operation lands verbatim in the report's log; certificates are not validated (transport behavior is measured, no credentials flow, nothing is changed).
* **`SiteVerdictService`** — rules in priority order: Blocked → LocalTlsBroken (every handshake fails *including controls* — the local stack, a real post-hardening condition) → HandshakeDropping → Steering → FarAway → Healthy (with an honest "fast now, but history shows bursts" split). Each verdict ships evidence lines and one reversible next step; nothing is auto-applied.

Read-only `diagnose_site` on the agent bridge runs the same pipeline (~30 s, DNS sampling tightened to 3 s). `SiteDoctorSelfTest\` compiles the shipping sources and proves: all fingerprint signals, every verdict rule, live loopback detection of the black-hole handshake shape (a listener that accepts TCP and never answers), and the caps. One SKIP is by design: a machine whose schannel cannot host TLS ("platform does not support ephemeral keys", observed after OS hardening) cannot run the healthy-server half — it says so loudly and still validates the rest.

Related capture-honesty fix in the same work: `TcpStreamCaptureService` now requests `SIO_RCVALL_IPLEVEL` first (both directions at the IP layer, no NIC promiscuous dependency) with `RCVALL_ON` fallback, tallies inbound vs outbound packets per session, and the Transmissions tab shows a banner when the session is one-way — a 0 in Down then reads "not observed", not "nothing came back".

The app collects **no usage telemetry** — nothing in it sends data anywhere on its own. (Usage analytics via Firebase/GA4 have been removed; the "Telemetry Opt-Out" section above is the Windows-telemetry hardening feature, unrelated.)

### Process Investigation (🔬 tab + `investigate_process` tool)

One composite read-only investigation per run — the whole "why is this transmitting?" playbook in a single call, joining facts the individual surfaces already record rather than collecting anything new:

* **`ProcessInvestigationService`** (Forensics core) — orchestrates `ProcessProvenanceService` (PID inquiry incl. the PID-reuse guard; enabled when a PID is given, best-effort on a live instance when a name is given), `TraceMetricsService` (the Traces-card traffic profile: frequency, destinations with classification, beacon regularity, recorded TLS volume, live connections), and the block-hit feed's **in-memory cache** (`Aggregates` — deliberately never the live Sysmon join, which is the slow path). Verdicts describe the numbers without claiming a baseline: Quiet → Internal-only → Outbound attempts, none completed → Actively blocked → Mixed, in priority order, each with evidence lines. Default window 6 h (cap 24) — the full-day archive scan is the slow path.
* **`InvestigateView`** (🔬 tab, SYSTEM group, opt-in via Settings → Advanced investigation) — Site-Doctor-shaped: subject box (name or PID), lookback picker, colored verdict banner, monospace report with Copy and Save (markdown under `%LOCALAPPDATA%\AutoCommand\reports\`).
* **`investigate_process`** on the agent bridge runs the same service and returns the structured JSON plus the identical `report_text`.

## MCP server (AgentProxy)

The "autocommand" MCP server AI clients connect to is **two halves**:

1. **`AutoCommand.AgentProxy.exe`** — the process clients actually spawn. A tiny asInvoker console exe (no WPF, no admin, no UAC) that reads `%LOCALAPPDATA%\AutoCommand\agent\session.json` (port + bearer token, present only while an AI session is active) on every incoming message and forwards each stdin JSON-RPC line to `127.0.0.1:<port>`. With no session it completes the MCP handshake itself ("offline" mode) and answers every tool call with setup guidance, so a client connects cleanly at any time.
2. **`AgentBridgeService`** — the listener inside the running (elevated) app: raw `TcpListener` on loopback, one minimal HTTP/1.1 request per connection, constant-time bearer-token compare, DNS-rebinding Host check, dispatch through `AgentToolRegistry`.

### Startup prerequisites (the DOTNET_ROOT trap)

Desktop MCP clients (Electron apps especially) routinely bundle their own .NET and export `DOTNET_ROOT` for every child they spawn — sometimes a runtime **older** than the one a framework-dependent apphost needs. The apphost then never falls back to the machine-wide install and exits before any managed code runs: the client just shows "server failed to start", with nothing actionable. For that reason the proxy ships as a **self-contained single-file exe** (runtime bundled, ~15 MB IL-trimmed; `release.ps1` publishes it into the zip's `tools\AgentProxy\`). It performs no framework lookup at all, so a hostile `DOTNET_ROOT` cannot break it.

The app's Register action installs that exe into `%LOCALAPPDATA%\AutoCommand\tools\v<version>\` (a fresh folder per app version — so a version bump always refreshes the deployed bits and a proxy still running from an older folder never locks the copy) and **preflights** it before any client config points at it: the exe must answer an MCP handshake both normally and under a poisoned `DOTNET_ROOT`, or registration refuses to claim success.

### The stable `tools\current` junction + auto-registration

Client configs are registered at the **stable junction path** `%LOCALAPPDATA%\AutoCommand\tools\current\AutoCommand.AgentProxy.exe`, where `current` is a directory junction the install step repoints at the newest complete `v<version>` folder. The registered string therefore never changes across app updates — the stale-registration class of bugs (every release stranding every client entry) is gone at the root; `FindStaleRegistrations` now only fires on genuinely dead links. A plain (non-junction) directory named `current` is never touched — the resolver falls back to the versioned path and says so.

On top of that sits **one-consent auto-registration** (Be My Guest tab): when a session starts and detected clients still lack the `autocommand` entry, one dialog offers *auto-register + keep updated*. Consent persists in `agent\auto-register.json` (`ask`/`auto`/`off`); `auto` also arms a startup self-heal (`McpAutoRegistration.RunStartupRepair`) that re-points moved/dead registrations through the same resolve → preflight → Register discipline as a manual click. Notification contract: a successful repair is never a modal — it renders one status line on the tab and a timestamped event in `agent\registration-events.jsonl` (client, outcome, old → new); a failed repair stays visible on the tab with the reason until fixed. Removal is first-class too: every registered client gets a **Remove** button (`Unregister` — same backup-before-write, only our key). Registering never starts anything: sessions still begin only from the Be My Guest tab, and with no session the proxy answers setup guidance.

### Legacy name-resolution doors (LLMNR · NetBIOS · mDNS)

Shields Up's Doors section carries three more doors — one board, one toggle each, all reversible (`NameResolutionDoors` in ShieldsUp.Core): **llmnr** = `EnableMulticast=0` policy (source-level; kills the LLMNR-poisoning credential-theft class), **netbios** = `NetbiosOptions=2` on every `Tcpip_` interface (per-GUID snapshot; *Partial* is a first-class state — "2 of 3 adapters" is never flattened to binary; applies on adapter restart/reboot), **mdns** = a firewall-scoped block of UDP 5353 multicast under its own rule group — network-level only, because Windows ships no source switch, and the evidence string says so. Snapshots live in `name-resolution-doors.json` beside the other ShieldsUp state; re-open restores exact previous values and refuses honestly when no snapshot exists. `get_shieldsup_status` carries each door's config **plus a live 24 h chatter count** (dropped UDP 137/5355/5353 attempts from the block-hit feed — attempts, never bytes), so config and consequence are read in one place; `close_shieldsup_door` accepts `llmnr | netbios | mdns` with the same confirm-every-call, re-open-only-in-the-tab contract as the other doors.

### Protocol

Supported `protocolVersion` values (both halves, kept identical): **2024-11-05, 2025-03-26, 2025-06-18**. A supported version is echoed; anything else is answered with the newest supported one (never blind-echoed — echoing "1999-01-01" used to claim a protocol we do not speak). Requests other than `initialize`/`ping` before initialization are refused with `-32002`; `resources/*` and `prompts/*` answer `-32601` (honestly unimplemented). Forwarding failures when the app session goes away answer `-32603` with guidance text. `serverInfo` is identical offline and online (`autocommand` / "AutoCommand (agent bridge)" / app version) so client UIs never relabel the server when a session flips mid-connection.

### Offline vs online

The proxy re-reads `session.json` on every message, so a session started after the client connected takes effect on the next call. The state flip emits exactly one `notifications/tools/list_changed` — only after the response to the in-flight message and only for clients that completed initialization. Proxy lifetimes (spawn parent, client name, stop reason) are appended to the same `%LOCALAPPDATA%\AutoCommand\agent\activity.jsonl` the app writes; stdout stays JSON-RPC only. A parent-PID watchdog plus stdin EOF guarantee the proxy never outlives its client.

### Testing by hand

```powershell
# full suite: publishes the self-contained proxy like release.ps1, then drives
# offline/online/flip/restart/error-code/poisoned-DOTNET_ROOT cases
powershell -File test-agent-proxy.ps1

# install-decision logic (versioned refresh, locked files, fallbacks)
dotnet run --project ProxyInstallSelfTest

# bridge end-to-end (starts the elevated app headless - UAC prompt)
powershell -File test-agent-bridge.ps1

# one manual handshake against the deployed copy
$exe = "$env:LOCALAPPDATA\AutoCommand\tools\AutoCommand.AgentProxy.exe"
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"hand-test","version":"0"}}}',
'{"jsonrpc":"2.0","method":"notifications/initialized"}',
'{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | & $exe
```
