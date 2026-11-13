# svchost-watch

Vendored inside the AutoCommand repository (`dparksports/autocommand-windows`,
this folder). Formerly a standalone private repository
(`dparksports/svchost-watch`, archived); the sibling clone is no longer needed.

Procmon-style network tracing + pattern analysis for `svchost.exe`, as a single
.NET 10 project. Integrated into the AutoCommand app as the
**🔬 Svchost Trace** tab — the app links `SvchostAnalyzer.Core` directly and
runs captures in-process. The `SvchostAnalyzer` CLI here is a dev/test face of
the same engine (`capture` / `analyze`); it is not shipped with releases.

## What it does

**capture** — polls WMI + netstat at 1s (non-elevated friendly; Sysmon/ETW needs
admin, this degrades gracefully) and writes synchronized JSONL event streams:

| type | meaning |
|---|---|
| `baseline` / `spawn` | svchost instance seen, with **parent process**, hosted services, creation time, command line, and identity fields `k`/`s` (-k group · -s self-declared service) plus `mismatch`/`noK` masquerade markers when the command line is readable |
| `connect` / `disconnect` | TCP destination opened/closed, with duration (`preexisting:true` = already open at capture start) |
| `bytes` | cumulative `Read/WriteTransferCount` samples per network-active PID |
| `exit` | instance gone |

Baseline is **batched** (one WMI roundtrip per table) — the retired PowerShell
predecessor took ~45 s on 80 instances querying per-PID; this is instant.

**analyze** — pattern detection over traces:

1. **Spawn genealogy** — every parent recorded; `parent != services.exe` = FLAG.
2. **Respawn loops** — same service spawning ≥4× in the window = FLAG.
3. **Destination classification** — Microsoft/Azure, Akamai, Gcore
   (session-verified ranges); anything else = UNCLASSIFIED → RDAP it
   (`https://rdap.org/ip/<ip>`), not auto-condemned.
4. **Beacon regularity** — coefficient of variation of connect intervals per
   (service, IP); CV < 0.35 with n ≥ 4 = REGULAR = beacon-like = FLAG.
5. **Upload dominance** — sent > 3 MB and > 3× received = FLAG.
6. **Identity corroboration** — parses each readable command line's
   `-k <group>` / `-s <service>` and checks the `-s` claim against the
   SCM-resident services for that PID (per-user services match on their
   `template_LUID` instantiation). A contradicting `-s`, or a readable line
   with no `-k` at all (the SCM always passes -k), = FLAG. Hidden command
   lines — non-elevated WMI cannot read SYSTEM svchost lines, the normal
   case for 66 of 74 instances — are counted and labeled, never flagged.

Exit codes: `0` clean, the flag count otherwise (nonzero = flags raised;
`1` usage error, `3` capture already running) — schedulable.

## Usage

```bat
cd svchost-watch\SvchostAnalyzer
dotnet build

:: capture 5 minutes
dotnet run --no-build -- capture --seconds 300 --out C:\temp\trace.jsonl

:: analyze (same schema as the AutoCommand tab's Export JSONL)
dotnet run --no-build -- analyze C:\temp\trace.jsonl
```

## Service mode (start / stop / auto-start on reboot)

```bat
:: run until killed or until the stop-file appears (service mode)
SvchostAnalyzer capture --seconds 0 --max-size-mb 200 --out trace.jsonl --stop-file stop.sentinel

:: stop it gracefully from anywhere (killing the process is also safe —
:: every event is its own appended JSONL line, so a killed trace stays valid)
echo stop > stop.sentinel
```

- `--seconds 0` = run indefinitely; `--max-size-mb N` rotates the trace at N MB
  (`trace-1.jsonl`, `trace-2.jsonl`, … — pass all parts to `analyze`, wildcards OK).
- A `Global\SvchostWatch.CaptureMutex` guarantees a single capture instance —
  a second one exits immediately with code 3. This is what makes auto-start
  and manual start coexist safely.

**Auto-start on boot is implemented as an HKCU Run key** (`AutoCommand-SvchostWatch`),
toggled from the AutoCommand **Svchost Trace** tab. Design note: scheduled tasks
were tried first but are elevation-gated here for standard users (`schtasks /tr`
caps at 261 chars; `Register-ScheduledTask` returns Access Denied without admin),
while a Run key needs no UAC and starts at logon. The trade-off — no automatic
crash-restart — is acceptable because captures are kill-safe and deduplicated;
if you need true service semantics later, wrap the collector in a Worker Service.

## Files

- `SvchostAnalyzer.Core/SvchostIdentity.cs` — the shared `-k`/`-s` parser +
  SCM corroboration check (one definition of svchost identity, used by the
  analyzer and the AutoCommand Process Monitor / PID Inquiry)
- `SvchostAnalyzer.Core/CaptureEngine.cs` — in-process WMI + TCP table capture
- `SvchostAnalyzer.Core/TraceAnalyzer.cs` — pattern detection over JSONL traces

## Verified behavior

- Synthetic trace → 6/6 detectors fire (6 flags), nonzero exit.
- Live capture → 81 instances, all parented by `services.exe`, 0 flags, exit 0.
- Live capture (2026-10-14, identity fields): 74 instances · 8 readable
  command lines (per-user service hosts) · 66 hidden — every readable line
  corroborates its SCM services, 0 flags.
- JSONL schema shared with the AutoCommand tab, so GUI exports analyze here
  and CLI captures replay in the GUI's report format.

## Known limitations

- 1 s polling can miss sub-second-lived processes (Sysmon closes that gap if
  you can run elevated).
- IPv6 destinations classify as `IPv6/other`.
- Range table is deliberately conservative; unknown ≠ malicious — RDAP first.
