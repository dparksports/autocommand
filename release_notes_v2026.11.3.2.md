# AutoCommand - v2026.11.3.2

The headless agent host now works on machines without any .NET installed -
no runtime install required, ever.

## What changed

- **AgentHost launcher (AgentHost\AutoCommand.AgentHost.cmd).** Scripts get
  one entry point that always works: when a .NET 10 runtime is present it
  runs the framework-dependent exe directly (millisecond boots - the reason
  this tool exists), aiming the runtime resolution at the same dotnet the
  probe validated, so portable PATH-only dotnet installs resolve too. When
  no .NET 10 exists, the launcher falls back to the app's own embedded
  runtime via AutoCommand.exe --agent-headless - the app ships
  self-contained, so the no-runtime case needs nothing installed. Both
  paths share the same session semantics: same bridge, same tools, mutating
  tools permanently denied, one session at a time.
- **Honest docs.** The AgentHost README and the Be My Guest section of the
  README now lead with the launcher and state the runtime trade-offs and
  the DOTNET_ROOT caveat for MCP-style scripts.

## Notes

- Calling the exe directly still requires the .NET 10 runtime - the launcher
  exists so scripts don't have to care.
- Existing allow-list behavior from v2026.11.3.1 (tamper-evident ledger,
  protected-surface verdicts, re-arm) is unchanged.
