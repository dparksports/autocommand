# v2026.11.8 — the three-day fuse

## The bug

AutoCommand registered its own logon task with:

```
schtasks /create /tn "AutoCommandStartupTask" /tr "<exe>" /sc onlogon /rl highest /f
```

That command writes no `<ExecutionTimeLimit>`, so Task Scheduler supplied its
own default — **PT72H** — and terminated the task three days after the logon
that started it. PowerShell and Task Scheduler never surfaced this anywhere the
user or the app could see it.

Field evidence from this development machine:

| When | What |
|---|---|
| 2026-11-03 23:04:35 | `\AutoCommandStartupTask` registered (author `Z690\honey`) |
| 2026-11-05 20:05:05 | boot; logon trigger starts the app |
| 2026-11-08 20:05:22 | Task Scheduler **event 329** — instance terminated for exceeding its execution time limit; 102/201 record return `0x8007050B` |
| 2026-11-08 20:06:27 | user relaunches the app by hand (parent `explorer.exe`) |

Exactly PT72H after the logon. `crash.log` was absent and there was no WER
report, because a termination is not a crash — which is why the app appeared to
vanish for no reason.

**Honest note on the termination path.** The app's own `activity.jsonl` records
`session stopped` at 20:05:22.577 — managed shutdown code ran at the same
second the Scheduler reports the termination. The two records disagree about
*how* the process ended. Nothing here depends on resolving that: the missing
limit and the PT72H timing are not in doubt, and either way the fix is the same.

## What changed

- **`ScheduledTaskGuard`** (ShieldsUp.Core): reads the *registered* task back
  and repairs the three settings that decide whether a long-lived watcher
  survives — `ExecutionTimeLimit` → `PT0S`, plus the two battery defaults.
  `Inspect`, `Repair` and `EnsureUnlimited` never throw; an unreadable task is
  reported unhealthy with the reason.
- **Both task creators normalise at creation.** `FreshSetupService` and
  `ShieldsUp`'s `LogonTaskService` had the identical defect
  (`ShieldsUpStartupTask` would also have died on day three). Creation now
  succeeds only if the task ends up unlimited.
- **Startup repairs a poisoned task.** An upgraded build cures the task an
  older build left behind. Existence was never the right test: the old code
  reported a 72-hour task as healthy forever, and the affected user is exactly
  the one who never opens Settings.
- **Liveness, so silence stops looking like success.**
  - `agent\heartbeat.json`, rewritten every 30 s.
  - A clean exit **deletes** it. That inversion is deliberate: a "clean = true"
    flag written on exit cannot be trusted, because exit is the path that does
    not run when a process is killed, and the path a crash truncates. A file
    that must be removed to mean "fine" fails safe.
  - Next start: a leftover beat whose pid is gone is an abrupt end by
    construction → one line in `agent\deaths.jsonl`.
  - When Task Scheduler's channel is readable, event 329 names the cause
    (`task-time-limit` vs `abrupt`); when it is not, the death is still
    recorded, just unattributed.
  - The user gets one plain-English dialog — *"AutoCommand was stopped by
    Windows at 8:05 PM because my own startup entry had a three-day time limit.
    That was my bug, not a problem with your PC."* — never a hex code, never an
    event id.
- **`StartupHealthSelfTest`** — 24 offline checks pinning the health matrix, the
  cause table, and the clean-exit inversion. Added to the strict CI gate.

## Not in this release, on purpose

- **Evidence-bundle UI and token redaction.** `session.json` carries the bearer
  token for the loopback bridge; a bundle feature must redact it, and doing that
  properly is its own change. The incident bundle built by hand during
  diagnosis stays out of the tree.
- **Sysmon EID 10 process-access arming.** That makes a future killer
  attributable rather than reconstructed, but it is a shipped Sysmon config, not
  a code change.

## Verification

- `dotnet build AutoCommand.csproj -c Release` — 0 errors (6 pre-existing
  NU1900 connectivity warnings, expected on an offline machine).
- `StartupHealthSelfTest` — 24/24 pass.
- Strict suites: `NetWatch`, `OneSettingsCadence`, `Contain`, `ProxyInstall`,
  `Bridge`, `PyTrace`, `Harden`, `Wsl`, `StartupHealth` all pass locally.
  `InterceptSelfTest` fails in this sandbox inside `RestoreWininetProxy`
  (registry access), a subsystem this change does not touch; it is reported as
  an environment failure, not a code failure.
