# v2026.11.10.1 — Blocks that explain themselves

## The problem

Two live incidents from one machine. First: a monitor row for PID 4
("System") produced a literal `AC-BLOCK-APP System` firewall rule —
program set to the string "System" — which starves every kernel-mode
socket (SMB client, http.sys, WSK sockets of VPN/EDR drivers) and only
looks harmless until the day one of them is needed. Second: blocking
anything showed a bare path or IP with zero context — users decided
without the investigation (who is this image, what shape is its
traffic, is it already being blocked) that the app's own
`investigate_process` bridge tool can produce in seconds.

## What changed

**Block Guard (refuse / warn).** The process-block path now runs every
subject through `BlockGuard` before the confirmation dialog:

- **Kernel images** (`System`, `Idle`, `Registry` — the no-path
  processes) are **refused outright**, with the explanation of what a
  kernel-socket block breaks and the protocol-level alternative
  (disable NetBIOS over TCP/IP; block the specific remote IP).
- **Security-critical images** (`lsass`, `winlogon`, `wininit`,
  `csrss`, `smss`, `fontdrvhost`) escalate the dialog warning: domain
  auth / logon plumbing, spelled out.

**Pre-block brief.** Both block dialogs (process and remote IP) now
carry a compact live investigation from the new
`BlockFeedbackService` — the same join behind
`investigate_process`: who the image is (provenance verdict —
including "Kernel process" for PID 4), its traffic shape (connects in
window, ~per-hour, top destination with classification), whether it is
already being blocked with drops counted, and the honest verdict
headline. After blocking, the brief reminds what evidence to watch:
attempts drop, bytes stay zero, and the Blocked tab shows
contained / stale / leak.

Both are covered by six new ContainSelfTest checks (guard decisions
for bare names and paths, case-insensitivity, the empty subject).

## Notes

- Full local CI before release: ContainSelfTest (all 103 checks),
  HardenSelfTest, ProxyInstallSelfTest, BridgeSelfTest pass; main app
  builds clean. The InterceptSelfTest journal-recovery failures
  remain pre-existing on a clean checkout of v2026.11.9.2 (noted in
  the v2026.11.10 notes) and are untouched here.
