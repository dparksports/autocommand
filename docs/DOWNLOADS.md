# Download history across the AutoCommand repositories

Snapshot taken `2026-11-01T03:43:35Z` (UTC), after the AutoCommand III consolidation into this
repository. Both AutoCommand II and III history, tags and releases now live here.

**Release retention policy:** one release per publish-day (the day's latest) is kept with
its binaries; older same-day releases remain as git tags with notes in the [consolidated release notes](release-notes-history.txt),
and their binaries are not re-hosted.

> These numbers are **asset requests recorded by GitHub** - raw hits on release-asset URLs,
> not unique users. Source archives, clones, and mirrors are not counted. GitHub cannot
> migrate counters, so re-uploaded assets start at zero; this file preserves the true
> history. The full per-asset record lives in
> [download-history.json](download-history.json) (earlier captures kept in git history).

## Totals by repository

| repository | releases with assets | assets | recorded requests |
|---|---:|---:|---:|
| dparksports/autocommand-windows | 7 | 21 | 24 |
| dparksports/autocommand-ii-archive | 13 | 39 | 7 |
| dparksports/autocommand-iii | 1 | 3 | 5 |
| dparksports/autocommand-link | 1 | 3 | 0 |
| **total** | | **66** | **36** |

## Versions with recorded requests

| repo | version | zip requests | all assets |
|---|---|---:|---:|
| autocommand-windows | `v2026.10.20.6` | 2 | 4 |
| autocommand-windows | `v2026.10.21.1` | 3 | 6 |
| autocommand-windows | `v2026.10.25.4` | 2 | 3 |
| autocommand-windows | `v2026.10.27.9` | 2 | 5 |
| autocommand-windows | `v2026.10.28.2` | 1 | 2 |
| autocommand-windows | `v2026.10.29.2` | 1 | 4 |
| autocommand-ii-archive | `v2026.10.27.3` | 1 | 1 |
| autocommand-ii-archive | `v2026.10.27.7` | 1 | 2 |
| autocommand-ii-archive | `v2026.10.27.9` | 1 | 1 |
| autocommand-ii-archive | `v2026.10.28` | 1 | 1 |
| autocommand-ii-archive | `v2026.10.29.1` | 1 | 1 |
| autocommand-ii-archive | `v2026.10.29.2` | 1 | 1 |
| autocommand-iii | `v2026.10.30.30` | 3 | 5 |

## Migration notes

- Re-created releases were byte-identical: every zip matched the `SHA256SUMS.txt` published
  with it before upload.
- Same-day releases pruned under the retention policy above keep their tags; the tags pin
  every commit, so no history is lost.
- Old deep links keep working: the source repos are renamed (not deleted), so GitHub
  redirects `/releases/download/...` URLs.
