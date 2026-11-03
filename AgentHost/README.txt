AutoCommand AgentHost — headless AI-access session (no window).

Run (recommended):  AutoCommand.AgentHost.cmd [seconds]
  The launcher probes for a .NET 10 runtime. If one is installed it runs
  the fast framework-dependent exe below (milliseconds to boot); if not,
  it reuses the runtime embedded in the app itself via
  AutoCommand.exe --agent-headless — same bridge, same tools, same rules,
  nothing extra to install. Both accept the optional auto-stop seconds
  and stop when stdin closes or Ctrl+C.

Direct (no launcher):  AutoCommand.AgentHost.exe [seconds]
  Requires the .NET 10 runtime. The main AutoCommand.exe ships
  self-contained and needs nothing installed; this small console tool is
  framework-dependent on purpose (scripts boot it in milliseconds). If
  Windows reports a missing runtime, use the launcher above instead — or
  install the .NET 10 Runtime from
  https://dotnet.microsoft.com/download/dotnet/10.0 — or skip this tool
  entirely and use the Be My Guest tab inside AutoCommand instead: same
  tools, same rules, inside the window you already have.

Notes:
- Refuses to start when another AutoCommand instance (app or host) is
  already running — one session at a time (both launcher paths enforce it).
- Mutating tools are permanently denied here: no confirmation dialog
  exists to ask you, so a headless session can answer questions and
  never change anything (both launcher paths).
- Scripts that export their own DOTNET_ROOT (some MCP clients do): a
  stale DOTNET_ROOT pointing at an older runtime wins over the launcher's
  probe. Clear the variable for AutoCommand sessions, or call the exe /
  app paths directly.
