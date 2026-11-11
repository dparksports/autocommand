# Security policy

AutoCommand is a security tool — it manages your firewall, instruments TLS for environments you explicitly opt in, and watches process spawns. Reports against the tool itself are taken seriously and handled privately.

## What counts as a security issue here

Broadly: anything that lets malware, an unprivileged user, or a remote party **bypass, abuse, or weaponize** AutoCommand's own machinery. For example:

- A way to make the app create/alter firewall rules, exclusions, or blocks without the confirmation flow
- Weaknesses in the TLS keylog handling (`%LOCALAPPDATA%\AutoCommand\pytrace\sslkeys.log` — ACL bypass, leaking to other users, surviving app exit)
- Injecting a fake python environment or audit-hook payload that gets installed with elevated rights
- Getting the Security Enforcer or Svchost analyzer to execute attacker-controlled content
- Crashes/hangs in the capture paths reachable from a non-admin context

"Windows itself has a flaw" or "this blocked process is suspicious" are **not** security issues against AutoCommand — those belong in [Discussions](https://github.com/dparksports/autocommand/discussions) or a [bug report](https://github.com/dparksports/autocommand/issues/new?template=bug_report.yml).

## How to report

**Preferred — GitHub private vulnerability reporting:**

👉 [Report a vulnerability](https://github.com/dparksports/autocommand/security/advisories/new)

This reaches the maintainer privately and lets us coordinate a fix and advisory before anything is public. This is currently the only reporting channel: it needs a (free) GitHub account, and an email address may be added here once one is actually monitored — a dead inbox is worse than none.

**Please do not open public issues, discussions, or PRs describing a vulnerability** — a working bypass posted publicly puts every current user at risk before a fix ships.

## Include in your report

- AutoCommand build (Settings → About) and Windows version
- Whether the app was running elevated
- Step-by-step reproduction, or the exact input that triggers it
- What you expected the app to enforce vs. what actually happened
- Impact as you see it (who can do what, from where)

## Expectations

This is a single-maintainer, Apache-2.0 open-source project: reports are acknowledged as fast as life allows (usually within a few days), fixes ship in the next release, and credited disclosures get a mention in the release notes unless you prefer to stay anonymous. Please give reasonable time for a fix before public disclosure.
