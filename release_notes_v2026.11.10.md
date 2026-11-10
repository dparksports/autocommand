# v2026.11.10 — Blocks that hold, honest opt-outs, zero-touch AI access

Three features that came out of one live investigation: a blocked
`msedgewebview2.exe` that kept "transmitting", a telemetry opt-out that
didn't touch the traffic it was blamed for, and an MCP server that had
to be wired into each AI client by hand.

## 1. Name-blocks now cover every copy of the binary

Windows Firewall enforces an app rule by exact image path, and binaries
move: WebView2 lives in a versioned folder that is deleted on every
runtime update, and ships in a second location under
`System32\Microsoft-Edge-WebView`. A block pinned to the one path you
saw goes inert while the process keeps trying from the new one.

`AppBlockCoverageService` already extended coverage when a blocked exe
*spawned* at a new path (Sysmon EID 1) and swept running processes at
startup. This release adds the leg that holds **without Sysmon and
before anything runs**: a periodic disk sweep enumerates every on-disk
copy worth covering — sibling version folders of known-covered paths
(only when the parent folder is version-named, so a blocked
`C:\Tools\upd.exe` never scans the drive) plus the documented extra
install roots of known multi-root binaries (WebView2's three
locations, extensible by name). Coverage also fires the moment a new
name enters the block list, not at the next hourly pass. Every
extension lands in the same `app-block-extensions.jsonl` audit trail.

## 2. Windows-search feature opt-outs — with honest wording

The biggest talker in the Phone Home table is SearchHost's WebView2
polling Bing suggestion/highlight endpoints — **feature traffic, not
diagnostic data**, so no diagnostics switch touches it. The Shields Up
vendor table gains three switches, each snapshotted and reversible:

- `DisableSearchBoxSuggestions` — Bing suggestions & search highlights
- `DisableCloudOptimizedContent` — the cloud-content pipeline
- `IsDynamicSearchBoxEnabled` — web results in the search box

They are labeled what they are (`switch_kind: feature`): the state
reads **"Off at the source"**, never "stopped" — and the rule text
says why: opt-out reduces at the source; only a firewall block proves
zero bytes (`verify_block_containment`). `opt_out_telemetry` now also
returns a **connects/hr baseline at flip time** for rules with a
traffic process, so "did the rate actually drop?" has its before
number in the same response. The registry write allow-list gains
exactly one user-scope key (the search box's own settings); everything
else stays confined to policy prefixes, and a new self-test replays
every shipped rule against the allow-list.

## 3. MCP auto-registration: one consent, then zero-touch

Registering AutoCommand into each AI client (ZCode, Cursor, Windsurf,
VS Code, Claude Desktop, Gemini) was a per-client button click — and
every app update stranded every registration, because configs pinned
`tools\v<version>\...`.

- **Stable `tools\current` junction** — client configs are now written
  at a path that never changes; the install step repoints the junction
  at the newest complete versioned folder. A plain directory named
  `current` is never touched. Registered strings survive every update;
  stale detection now only fires on genuinely dead links.
- **One-consent auto-registration** — when a session starts and
  detected clients lack the `autocommand` entry, one dialog offers
  *auto-register + keep updated* (Yes / ask-next-time / never). Consent
  persists in `agent\auto-register.json`; only detected clients are
  ever written.
- **Startup self-heal** (consented mode only) re-points moved or dead
  registrations through the same resolve → preflight → Register
  discipline as a manual click. A successful repair is never a modal:
  one status line on the Be My Guest tab plus a timestamped event in
  `agent\registration-events.jsonl` (client, outcome, old → new). A
  failed repair stays visible on the tab with the reason until fixed.
- **First-class removal** — every registered client gets a Remove
  button: same backup-before-write discipline, only our entry, verified
  by re-reading.

Registering still never starts anything: sessions begin only from the
Be My Guest tab, and with no session the proxy answers clients with
setup guidance.

## Notes

- Full local CI before release: 15/16 self-test suites pass. The two
  InterceptSelfTest journal-recovery failures reproduce on a clean
  checkout of the previous release — pre-existing, not from this
  release; they are machine-state-sensitive checks unchanged here.
- New/extended suites: ContainSelfTest (5 disk-sweep checks),
  HardenSelfTest (5 rule-table invariants), ProxyInstallSelfTest
  (junction stability across version bumps, plain-dir refusal,
  unregister round-trip, bulk-register scope).
