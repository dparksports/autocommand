# AutoCommand — v2026.11.2.1

Same-day follow-up to v2026.11.2 with two Spawn Watches fixes found in
the first hours of real use.

## What changed

- **The Spawn Watches tab renders its data.** The shipped tab bound its
  hits grid, rule cards and hit counts to public *fields* on the row view
  models — WPF bindings resolve CLR properties only, so every binding
  silently produced nothing and the tab rendered blank while the service
  indexed hits correctly on disk. The view models now use public
  properties (the BlockRowVm house pattern). Backend behavior unchanged.
- **backgroundTaskHost joins the visible feed.** It was part of the
  starter allowlist, so svchost spawning it never counted as a hit. It is
  a legitimate service-host child worth seeing; it left the starter
  allowlist, and existing machines keep full authority over their own
  `allowlist.txt` hand-edits.
