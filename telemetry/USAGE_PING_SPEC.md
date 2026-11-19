# Opt-in Install Count — design spec (AutoCommand & Shields Up)

**Purpose:** count how many people actually run the apps — **unique
installs**, not launches — with data that stays as close to anonymous as
counting uniquely allows: **one random id per install, and nothing else
that identifies anyone.** The id is invented on the user's machine (a fresh
`Guid`), is not derived from hardware, account, or IP, and is never stored
alongside anything that could connect it to a person.

**One-line summary:** an **opt-in, off-by-default** daily ping carrying
app version + a random install id. The server dedupes by id: one row per
unique install ever, one row per install per active day. Country comes
from the edge; **no IP address is ever read, stored, or forwarded**.

*History:* rev 1 of this design (shipped 2026-10-15) carried no identifier
at all and could only count raw daily pings — so one enthusiastic user
testing daily inflated the total forever. Rev 2 (this spec) adds the random
id precisely so repeats count once. The trade is documented honestly in
"Legal footing" below: a random id is pseudonymous data, so we treat it as
personal data and build to that standard.

## What the client sends

```json
POST /v1/ping
{ "a": "autocommand",          // app: autocommand | shields-up
  "v": "261015",               // build date, compact — derived from the app version's date (app versions stay 2026.10.NN)
  "o": "10.0.26300",           // Windows OS build
  "i": "0f4bf1a2c6d34e568a90b1c2d3e4f506" }  // random install id (32 hex, Guid "N")
```

That is the entire payload. No hostnames, process names, command lines,
hardware ids, user identifiers, behavioral events, and no IP retention.
The `i` id: created by the app with `Guid.NewGuid()`, persisted in the
count's own registry key (`HKCU\...\UsagePing\InstallId`), regenerated
fresh — unlinkable to the old — if the user deletes the key and later
opts back in. The server rejects any ping whose id is not exactly 32 hex
chars, so pre-rev-2 builds (no id) and junk requests are never counted.

## How dedup works

Two layers:

- **Client-side once-per-day** (unchanged): the app records the last UTC
  day it pinged (`LastSentDay`) and skips if today was already sent.
- **Server-side, authoritative**: `installs.id` is a PRIMARY KEY (one row
  per unique install, ever) and `daily_active(day, install_id)` is a
  composite PRIMARY KEY (one row per install per day). `ON CONFLICT DO
  NOTHING` makes double-counting structurally impossible — a wiped client
  registry, a re-unzipped folder, or a hundred relaunches still yields one
  row per id per day.

Known edges, accepted deliberately: reinstalling Windows (or deleting the
registry key) and re-opting-in creates a new id, so it counts as a new
install — same behavior as every "unique install" metric in the industry.
A user on two machines counts as two installs (correctly).

## Consent model

- **Off by default.** Nothing is sent until the user explicitly says yes.
- **Three states** in `HKCU\Software\AutoCommand\UsagePing\Consent`:
  `ask` (default) → dialog offered at most **3 times**, then never again;
  `yes`; `no`.
- **The dialog states in plain English exactly what is sent — including
  the random id and what it is not** (not from hardware/account/IP) — and
  how to withdraw (delete the registry key; that erases the id too).
- **Consent revision tracking** (`ConsentRev`): the registry stores which
  payload shape the user agreed to. A "yes" given under an older shape is
  downgraded to `ask` once, so the current dialog can re-ask (informed
  consent — rev 1 users were promised "no id at all"). A permanent `no`
  is never converted back into a question.
- The dialog remains for two reasons: it is good product hygiene for a
  privacy tool, and the registry writes are terminal-equipment storage
  under ePrivacy Art. 5(3) — consent keeps that clean too.

## Server design (Cloudflare Worker + D1)

Three tables (see `schema.sql`; the schema is idempotent — safe to re-run
on the live database):

| Table | Grain | Purpose |
|---|---|---|
| `installs` | one row per unique install (`id` PK) | the headline unique-installs number; country + first-seen day |
| `daily_active` | one row per install per day (`day, install_id` PK) | daily actives, version adoption, per-day countries |
| `daily_rollup` | (legacy) daily aggregate pings | pre-rev-2 history; kept readable, no longer written |

- Country comes from `request.cf.country` — Cloudflare derives it at the
  edge; **our code never reads, stores, or forwards an IP address**. The
  guarantee is architectural, not a promise.
- Id validation is strict: `/^[0-9a-f]{32}$/` or HTTP 400 — the tables
  can only ever hold well-formed random ids.
- No secrets beyond `ADMIN_TOKEN` for the stats endpoint. No salt,
  no cron. Rows are kept indefinitely because the only key anywhere is
  the client-invented random id — a leak reveals counts and random
  numbers, nothing about any person.

## Migration (rev 1 → rev 2, live deployment)

1. `npx wrangler d1 execute usage-ping --remote --file=schema.sql` — adds
   `installs` and `daily_active`; leaves `daily_rollup` untouched.
2. `npx wrangler deploy` — the new worker stops writing `daily_rollup`.
3. Effects, stated plainly: the all-time number restarts at 0 on deploy
   day (only ids seen from then on are counted); the daily series keeps
   its history by merging legacy days from `daily_rollup`; pre-rev-2
   client builds are rejected (400) and stop being counted until they
   update — their clients retry harmlessly once per launch.

### Public surface (the growth loop)

Because the data is pseudonymous-only by construction (random id + day +
country + version), it is publishable by design:

| Route | What |
|---|---|
| `GET /` | **The community count page** — self-contained HTML (no external assets, no tracking): unique-installs card, daily-actives chart, top countries, download buttons for both apps, and share buttons. This is the link users share with peers. |
| `GET /v1/graph` | Public JSON (CORS `*`, 5-min cache): `totals.total_installs`, merged daily series (365d), top-10 countries (by installs, suppressed under 5). |
| `GET /v1/badge` | Plain text: yesterday's distinct opt-in daily actives. |
| `GET /v1/stats` | Admin JSON (bearer `ADMIN_TOKEN`): per-app split, version adoption, countries, legacy totals. |

In-app entry points (AutoCommand): a "See the live community graph →" link
on the consent dialog and "📈 Community graph" / "🔗 Share AutoCommand"
buttons in Settings → Application Information (share copies the graph-page
URL, falling back to the GitHub releases link until the endpoint is
deployed). The loop users see: the number grows when peers install → the
graph proves it → one click shares the link that grows it.

## Metrics this yields

| Metric | How it's computed |
|---|---|
| **Unique installs (headline)** | `COUNT(*)` on `installs` — deduped forever by random id |
| Daily actives (opt-in) | `COUNT(*)` per day on `daily_active` — deduped per day |
| Version adoption | `daily_active` grouped by version, distinct ids (30-day window) |
| Country distribution | `installs` grouped by country (edge-derived, never an IP) |
| Opt-in rate (directional) | daily actives vs. release downloads |

**What the id buys, and what it still doesn't.** Cross-day dedup now
exists, so MAU/WAU and first-seen cohorts are *computable* — but the
public page intentionally publishes only unique installs and daily
actives. Cohort dashboards stay behind `ADMIN_TOKEN` if ever needed.
Retention-style tracking of persons remains impossible (nothing links an
id to a person), which is the point.

## Security & abuse model

**Trust model:** the client is open source, so it can hold no secret — the
count endpoint is unauthenticated *by design*. Everything downstream
assumes the endpoint receives hostile input.

| Threat | Defense | Status |
|---|---|---|
| Browser-based count inflation (malicious page POSTing from visitors) | `Content-Type: application/json` required — forces a CORS preflight the endpoint never grants, closing the "simple request" path | in worker |
| Garbage/hostile payload values | App allowlist; every field length-capped; country regex-validated (`^[A-Z]{2}$` else `??`); install id must match `^[0-9a-f]{32}$` | in worker |
| Same-id repeat spam (client bug, wiped registry, loops) | Primary-key dedup on `installs` and `daily_active` — repeats are `DO NOTHING`, not increments | in worker |
| SQL injection | Every query is static SQL with bound parameters — no string interpolation | in worker |
| Stored XSS via the public page | All data-driven strings HTML-escaped before insertion; country values server-validated; the page loads zero external assets | in worker page |
| **Fresh-id flood inflation** (`curl` loops minting new 32-hex ids) | **Accepted residual risk.** Dedup cannot help against unique fake ids. Mitigated by the plausibility anchor: opt-in installs can never legitimately exceed cumulative downloads (weekly cross-check vs. `pull-github-metrics.ps1`); anomalies are annotated in the data room, never silently deleted | process |
| Single-IP flood | WAF rate-limit rule on `POST /v1/ping` (recipe in server/DEPLOY.md #Hardening; needs a custom domain) | deploy-time |
| Small-number deanonymization (rare country × version) | Public `/v1/graph` suppresses country rows under 5 installs; admin feed keeps detail behind `ADMIN_TOKEN` | in worker |
| `ADMIN_TOKEN` leak | Random 36-byte value, gitignored file, rotation one-liner; guards reads of pseudonymous aggregates only | deploy-time |
| Cloudflare API token | Least-privilege scopes (Workers Scripts:Edit, D1:Edit), single account, deletable after setup | deploy-time |
| Endpoint hijack (lost/renamed worker) | Client sends only version + a random id and ignores response bodies — blast radius is a dropped count, not data | by design |
| DoS / cost runaway | Free tier caps fail closed (counting pauses; no spend); client retries silently on next launch | by design |

**The integrity story for investors** matters as much as the
confidentiality story: because the count is spoofable in principle, the
data room pairs the raw D1 exports with the methodology (this spec) and
the downloads ceiling cross-check — "here is exactly how spoofable it is,
and here is the independent anchor." That converts a weakness into a
credibility signal.

## Legal footing (summary — not legal advice)

Rev 1 could honestly say "genuinely anonymous, outside personal-data
scope." Rev 2 gives that up on purpose: a random id is **pseudonymous
data**, and under GDPR pseudonymous data stays in personal-data scope
(Recital 26 reads the other way only for truly anonymous data). So the
design treats the id as personal data and meets the resulting obligations
by construction:

- **GDPR/ePrivacy:** consent is the lawful basis and it is *informed* —
  the dialog discloses the id and what it is not, and rev-tracked consent
  (`ConsentRev`) re-asks anyone who agreed under the older no-id shape.
  Data minimization holds: the id plus day/country/version is the least
  data that can count uniquely. The right to erasure is one registry-key
  deletion away client-side, and the server-side row is a random number
  no one can trace back to the person who deleted it. ePrivacy
  terminal-equipment storage is consented like everything else.
- **CCPA/CPRA and state look-alikes:** no sale, no sharing, no
  cross-context behavioral profiling; processing is disclosed and opt-in,
  which exceeds the opt-out baseline those laws require.
- **Other regimes (LGPD, PIPEDA, APPI, PIPL):** the same three properties
  — consent before anything is sent, minimum data, easy full withdrawal —
  are the common denominator these laws expect for data of this kind.
  This is a design claim about intent, not a legal opinion and not a
  guarantee of compliance in every jurisdiction: if this ever matters
  commercially at scale, get counsel to review the current spec.
- If a future feature ever links the id to anything richer (account,
  sync, purchase), that feature — not this counter — carries its own
  compliance analysis, and this spec must be rewritten again first.

## Ship rules

1. The count code **and** the README/PRIVACY.md changes ship in the **same
   release**. Never one without the other.
2. The client no-ops unless the endpoint is configured (`UsagePingService.Endpoint`).
3. Document the endpoint hostname in TECHNICAL_NOTES so Black Hole users can
   verify the app does exactly what the dialog says.
4. Never add a field to the payload without rewriting this spec first — the
   spec is the contract — **and** bump `UsagePingService.CurrentConsentRev`
   so existing "yes" answers are re-asked against the new disclosure.
