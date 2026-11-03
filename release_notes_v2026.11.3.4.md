# AutoCommand — v2026.11.3.4

A follow-up release with no shipped-binary change: this one fixes the source
of the preserved SystemMonitor precursor tree (`systemmonitor/`, excluded
from the app build on purpose).

## What changed

- **Precursor connections table made whole and honest.** An audit of the
  classic app's GetUdpConnections/GetTcpConnections against the
  Engines.Watch kernel-table family found eight defects, all fixed in the
  `systemmonitor/` tree:
  - IPv6: AF_INET6 was defined and never queried — every IPv6 endpoint was
    invisible. TCP6/UDP6 owner-pid structs added; both tables enumerate
    both families.
  - Sizing race: a table that grew between the sizing probe and the fill
    silently produced an EMPTY snapshot; the probe now answers
    ERROR_INSUFFICIENT_BUFFER and a grown fill retries at the new size.
  - Semantics: UDP rows said "Listening" (a TCP concept) and vanished rows
    entered history as "Closed" — they now say "Bound" / "Unbound".
  - Mute collision: every UDP row's RemoteAddress is "-", so one mute muted
    every UDP row; mute keys are per-protocol now (TCP keeps the bare-IP
    contract WhoIs/clipboard rely on).
  - WhoIs guard: "-" was queued into the lookup pipeline like an IP;
    connectionless rows resolve to "UDP (bound, no remote)".
  - IsLocalIp: the "172.16." prefix check missed RFC1918 172.16.0.0/12
    (172.17–172.31 misclassified as non-local); proper /12 parse + ::1.
  - TCP remote port: carried in the struct, never rendered — new
    ConnectionItem.RemotePort (RemoteAddress stays a bare IP).
  - pid→name cache never expired: cleared per refresh cycle so a recycled
    pid cannot wear its previous tenant's name.

If you only run AutoCommand, nothing about this release changes your
install — the precursor tree does not compile into anything shipped.
