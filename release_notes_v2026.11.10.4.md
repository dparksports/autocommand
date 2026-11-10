# v2026.11.10.4 — Startup & Tasks: the persistence surface, on one board

## The problem

Shields Up covered network doors, phone-home, junk and OS switches — but
not the third classic surface: **persistence**. What runs at logon (Run
keys, Startup folders) and what runs on schedule (Task Scheduler) lived
nowhere in the app, even though the engines already existed
(`RegistryHelper.GetStartupItems`, the COM-based `TaskSchedulerService`
that replaced every schtasks.exe call, and the monitor's task
attribution).

## What changed

**A new Startup section in the Shields Up rail**, born directly in the
HIG card kit introduced in v2026.11.10.3 — large title, summary pill
("N third-party autostart(s)"), inset groups, one quiet card per item:

- **AT LOGON** — Run-key and Startup-folder entries. Registry values
  toggle by **snapshot-then-remove**: the exact command string is saved
  to `startup-state.json` before the value is deleted; restore is exact,
  and re-enabling something we never disabled refuses honestly. Folder
  shortcuts are listed but never touched by us — the button says why.
- **SCHEDULED TASKS** — third-party tasks listed individually (state ·
  action · user) with reversible Enable/Disable via the existing COM
  service; **Windows inbox tasks are counted, not listed** — the board
  stays human. Classification is location-based
  (`\Microsoft\Windows\` = inbox, everything else third-party) and says
  so — no signature claims.
- **Bridge**: a new read-only `get_startup_status` tool exposes the same
  surface to AI sessions (logon items with disabled-by-AutoCommand
  flags, third-party tasks, inbox count); mutations stay in the tab.

Four new HardenSelfTest checks pin the classification (inbox vs
third-party vs null-safe) and the registry-vs-folder toggle mapping.

## Also on this machine (not part of the build)

The two pending HKLM search policies from the SearchHost deactivation
ladder were applied and verified with this release's approval:
`DisableSearchBoxSuggestions=1`, `DisableCloudOptimizedContent=1`, plus
a fresh stop of the SearchHost tree. The full ladder is now complete
here: features off at the source, entry point hidden, dynamic search
box off, tree contained at zero bytes. Revert path:
`%LOCALAPPDATA%\AutoCommand\revert-searchhost.ps1`.

## Notes

Local CI before release: all 15 suites pass — including the
stub-parity tripwire (the AgentProxy offline list gained
`get_startup_status` in lockstep). RainSelfTest exceeded the sweep
window twice under release-day build load and passed cleanly with the
full window; its code path is untouched by this release. The two
InterceptSelfTest journal-recovery failures remain pre-existing on a
clean v2026.11.9.2 checkout (noted since v2026.11.10).
