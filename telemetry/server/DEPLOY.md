# Deploy the usage-count endpoint (~15 minutes, $0 at current scale)

The worker runs on Cloudflare's free tier (100,000 requests/day — far beyond
these apps' needs for years). It counts **unique installs**: the only key it
stores is the random id the app invents on the user's machine (never derived
from hardware, account, or IP), deduped by primary key so repeats can't
inflate the number. No IP address is ever read, stored, or forwarded by our
code — the country code arrives pre-derived at Cloudflare's edge
(`request.cf.country`). That guarantee is architectural.

The same worker also serves the **community graph page at its root** — the
public, shareable URL showing the live daily-actives chart, country mix, and
download/share buttons. That URL is what the in-app "Share AutoCommand"
button copies.

## One-time setup

```powershell
# 1. Cloudflare account (free): https://dash.cloudflare.com/sign-up
# 2. Node.js 18+ installed, then in this folder:
npm install -g wrangler
wrangler login

# 3. Create the D1 database
wrangler d1 create usage-ping
#    → copy the `database_id` it prints into wrangler.toml

# 4. Initialize the schema (three tables; idempotent — safe to re-run)
wrangler d1 execute usage-ping --remote --file=schema.sql

# 5. Set the single secret (paste any long random string when prompted)
wrangler secret put ADMIN_TOKEN

# 6. Deploy
wrangler deploy
#    → prints your URL, e.g. https://autocommand-usage-ping.<your-subdomain>.workers.dev
```

## Migrating the live deployment (pre–install-id → install-id)

The worker went live 2026-10-15 on the rev-1 schema (one `daily_rollup`
table, no ids). Rev 2 counts unique installs. Migrate in this order:

```powershell
# 1. Add the two new tables (installs, daily_active). Idempotent —
#    daily_rollup is left exactly as it is.
wrangler d1 execute usage-ping --remote --file=schema.sql

# 2. Deploy the rev-2 worker (it stops writing daily_rollup).
wrangler deploy
```

Effects, stated plainly (also in `../USAGE_PING_SPEC.md`):

- The **unique-installs number restarts at 0** on deploy day — only ids
  seen from then on are counted. The old raw-ping total stays queryable
  as `legacy` in `/v1/stats`, and the graph's daily series keeps its
  history by merging the legacy days in.
- Client builds from before the install id send pings without `i`; the
  worker rejects them (HTTP 400) and they are not counted until the app
  updates. Those builds retry harmlessly once per launch.
- Existing users who had said "yes" are **re-asked once** by the new app
  build (their original consent covered a no-id payload); users who said
  "no" are never re-asked.

## Wire the client

1. Put the deployed URL into `Services/UsagePingService.cs` → `Endpoint`
   constant in the app (`https://…workers.dev/v1/ping`), and set
   `AppName` (`autocommand` / `shields-up`) per app.
2. Ship it in the same release as the README/PRIVACY.md changes (see
   `../docs/INTEGRATION.md`).

## Day-to-day

> **Automated:** `powershell -File snapshot-usage.ps1 -Install` registers a
> weekly scheduled task that snapshots /v1/stats + GitHub downloads into
> `fundraising/metrics/history/` and runs the plausibility anchor. Details:
> `docs/WEEKLY_RITUAL.md`. The manual commands below still work.

```powershell
# Weekly numbers (the investor table):
curl -H "Authorization: Bearer <ADMIN_TOKEN>" https://<your-worker>/v1/stats

# The community graph page (open in a browser; this is the share URL):
start https://<your-worker>/

# Public daily-actives badge (optional, safe to expose — yesterday's opt-in DAU):
curl https://<your-worker>/v1/badge
```

What you get from `/v1/stats`: distinct daily-active series per app (last
240 days), country distribution, version adoption (30 days), install
totals, and the legacy raw-ping totals from before the install id. There
are no per-person metrics anywhere — the only key is a random id no one
can trace back to a person — by design.

Save the `/v1/stats` output weekly into `../../fundraising/metrics/` (see
`pull-github-metrics.ps1` for the download-count side) — that becomes the
traction time series for the raise. (Or let `snapshot-usage.ps1 -Install`
do it — see `docs/WEEKLY_RITUAL.md`.)

> **Operational note — fresh deploys:** the smoke tests can false-fail for
> about a minute after the very first deploy (the worker reports deployed
> before the D1 binding has propagated to every edge colo — transient
> 500/404). Re-run the script before diagnosing; it is idempotent. Verified
> live on the first-ever deploy: 5/6 FAILs, then all PASS on re-run with
> zero changes.

## Hardening (5 minutes, one-time)

**Rate-limit the count endpoint** — the one abuse vector left after the
worker's own gates (JSON-only content type kills the browser vector; app
allowlist + field truncation bound what a row can contain). A single IP
flooding `POST /v1/ping` is the remaining way to inflate counts:

1. Cloudflare dash → your domain (the workers.dev zone isn't rate-limited
   from the dash; a custom domain on the worker is) — if you stay on
   `*.workers.dev`, the practical mitigation is the plausibility check below.
2. With a custom domain: Security → WAF → Rate limiting rules →
   expression `(http.request.uri.path eq "/v1/ping")`, e.g. 30 requests / 10
   min / per IP, action Block for 1 hour.

**Plausibility anchor (do this regardless):** installs can never legitimately
exceed downloads. In the weekly snapshot ritual, compare that day's opt-in
DAU (and the unique-installs total) against cumulative downloads from
`pull-github-metrics.ps1` — a curve that explodes past the downloads ceiling
is spoofed (fresh random ids are free to mint), and you annotate it as such in
the data room rather than deleting it. Investigable raw data + methodology
beats silently "fixed" numbers.

**Token hygiene:**
- The Cloudflare API token: scope it to the one account; delete it after
  setup (re-create when you redeploy).
- `ADMIN_TOKEN` rotation: generate a new value, then
  `wrangler secret put ADMIN_TOKEN`, update `admin-token.txt`. It only
  guards reads of pseudonymous aggregates, but rotate it like any credential.
- Never commit `admin-token.txt` (gitignored) and never paste it in
  screenshots or issues.

**If the endpoint is ever abused:** you can null-route the abuse cheaply —
deploy with `ALLOWED_APPS` emptied (worker rejects everything, page keeps
rendering history) while you investigate. No user data is at risk in any
scenario; the only rows in the database are random ids plus day/country/version.
