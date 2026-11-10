# v2026.11.10.2 — The legacy name-resolution doors

## The problem

Windows enables three broadcast/multicast name-resolution protocols by
default: **NBNS** (UDP 137, 1990s NetBIOS), **LLMNR** (UDP 5355) and
**mDNS** (UDP 5353). Every DNS miss fans out to all of them, each packet
interrogates every host on the LAN segment, and LLMNR/NBNS poisoning is
a textbook credential-theft technique. The PID 4 mystery on the machine
that drove this release turned out to be exactly this: the kernel's
NetBIOS broadcasts, dropped by a block rule that shouldn't exist.

## What changed

**Three new doors on the Shields Up board** — one place, one toggle
each, all reversible (`NameResolutionDoors`):

- **LLMNR** — `EnableMulticast=0` policy, source-level. Status reads
  the live policy; previous value snapshotted and restored exactly.
- **NetBIOS** — `NetbiosOptions=2` on every `Tcpip_` interface, with a
  per-GUID snapshot. **Partial is a first-class state**: "2 of 3
  interfaces" is shown as Partial, never flattened to closed. Applies
  on adapter restart/reboot (the evidence says so).
- **mDNS** — a firewall-scoped outbound block of UDP 5353 multicast
  (224.0.0.251 / ff02::fb) under its own rule group, the clean revert
  unit. Labeled honestly: **network-level only** — Windows ships no
  source switch, and the door says so. Printer/Chromecast/AirPlay
  discovery stops while closed.

**Status carries consequence, not just config**: `get_shieldsup_status`
now includes each door's state *plus a live 24 h chatter count* —
dropped UDP 137/5355/5353 attempt totals from the block-hit feed
(attempts, never bytes). After closing a door, the same number becomes
the receipt. `close_shieldsup_door` accepts the three new ids with the
same confirm-every-call contract; re-opening stays a human decision in
the tab.

Snapshots persist in `name-resolution-doors.json` beside the other
ShieldsUp state; re-open without a snapshot refuses honestly instead of
guessing. The Doors rail dot counts the three new doors.

## Notes

- Local CI before release: HardenSelfTest (7 new door-state checks:
  Unknown/Closed/Partial/Open transitions, the absent-policy-means-open
  rule, rule-count semantics), ContainSelfTest, BridgeSelfTest and
  ProxyInstallSelfTest all pass; the app builds clean. The two
  InterceptSelfTest journal-recovery failures remain pre-existing on a
  clean v2026.11.9.2 checkout (noted since v2026.11.10) and are
  untouched.
