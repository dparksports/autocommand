# v2026.11.10.3 — Shields Up, redesigned for readability

A visual overhaul of all five Shields Up detail panels (Quick Scan,
Doors, Privacy, Junk, Hardening) following Apple HIG principles,
translated to the app's WPF idiom. **No behavior changes**: every
control name, handler, binding and refresh method is untouched — this
is a restyle with a XAML-only regression surface.

## The new anatomy

Every subtab now answers "am I OK?" before asking you to read:

- **Large title + one plain sentence** replace the shouting section
  headers — each page opens with its name (21 px, semibold) and a
  single line of what it does.
- **A summary pill** at the top right of every page — the page's whole
  verdict in one glance: "3 of 8 doors open", "2 vendors still on",
  "4 package(s) matched", "All switches set". Each pill is driven from
  the same aggregate the rail dot already computes (one code path, two
  faces: dot for the rail, pill for the page).
- **Inset groups** — iOS-Settings-style rounded containers under
  small-caps secondary headers. Doors reads as REMOTE ACCESS (5 rows) +
  LEGACY NAME RESOLUTION (3 rows); Hardening as NETWORK / SIGN-IN /
  HOSTS FILE.
- **One quiet card per item** — title, one line of plain evidence,
  action bottom-right. Row boundaries reveal on hover (direct
  manipulation), never in static chrome.
- **One button style for every action class** across all five subtabs:
  quiet, rounded, hairline border, hover tint, disabled dim — the
  mixed default-button styles are gone.

The kit is built entirely from the app's existing dynamic brushes, so
dark and light themes carry through unchanged, and it is exactly the
vocabulary the upcoming Startup & Tasks section will be born in.

## Verification

Local CI before release: all 15 self-test suites pass (BridgeSelfTest
and RainSelfTest pass on direct rerun — the sweep harness's shorter
timeouts and a live AI session holding session.json account for their
first-run noise; both are known environment sensitivities, and a
XAML-only change touches no engine code). The two InterceptSelfTest
journal-recovery failures remain pre-existing on a clean v2026.11.9.2
checkout (noted since v2026.11.10) and are untouched.
