-- Opt-in install-count schema — D1. Counting model: one row per unique
-- install (deduped by a random client-generated id) and one row per install
-- per active day. The id is pseudonymous (a Guid the app invents on the
-- user's machine), never derived from hardware/account/IP, and nothing
-- identifying is ever stored with it. No IP-derived values anywhere.
-- Idempotent: safe to re-run on the live database (daily_rollup untouched).

-- One row per unique install ever seen. ON CONFLICT DO NOTHING at write
-- time; COUNT(*) = the public "unique installs" number.
CREATE TABLE IF NOT EXISTS installs (
  id        TEXT PRIMARY KEY,     -- random install id: 32 hex chars (Guid "N")
  app       TEXT NOT NULL,        -- 'autocommand' | 'shields-up'
  country   TEXT NOT NULL,        -- ISO 3166-1 alpha-2 from request.cf.country, or '??'
  first_day TEXT NOT NULL         -- YYYY-MM-DD (UTC) the install was first seen
);

-- One row per install per active day. COUNT(*) per day = daily actives;
-- the primary key makes same-day repeats (re-launches, wiped LastSentDay)
-- impossible to double-count.
CREATE TABLE IF NOT EXISTS daily_active (
  day        TEXT NOT NULL,       -- YYYY-MM-DD (UTC)
  install_id TEXT NOT NULL,       -- references installs.id (by value; no FK so
                                -- rows stay insertable/ordered independently)
  app        TEXT NOT NULL,
  country    TEXT NOT NULL,
  version    TEXT NOT NULL,       -- "appversion/osbuild", first seen that day
  PRIMARY KEY (day, install_id)
);

-- Legacy: pre-installs-id daily aggregates (pings ≈ actives). Kept for
-- history — the graph merges these days in — but no longer written by the
-- worker. Contains no identifiers; retained indefinitely.
CREATE TABLE IF NOT EXISTS daily_rollup (
  day     TEXT NOT NULL,          -- YYYY-MM-DD (UTC)
  app     TEXT NOT NULL,          -- 'autocommand' | 'shields-up'
  country TEXT NOT NULL,          -- ISO 3166-1 alpha-2 from request.cf.country, or '??'
  version TEXT NOT NULL,          -- "appversion/osbuild"
  pings   INTEGER NOT NULL DEFAULT 0,  -- daily-active count (client pings at most once/day)
  PRIMARY KEY (day, app, country, version)
);
