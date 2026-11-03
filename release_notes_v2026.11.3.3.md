# AutoCommand - v2026.11.3.3

AI access lives in the Be My Guest tab only. The headless host is retired,
and with it the last reason anyone would ever need a separately installed
.NET runtime: every binary in the release zip now carries its own.

## What changed

- **Tab-only activation.** Sessions start from the Be My Guest tab - the
  Start button, or its "start automatically" option. There is no command-line
  activation anymore: the `--agent-headless` launch path is removed from the
  app, and the headless AgentHost console tool (and yesterday's launcher
  shim for it) are retired from the codebase and the zip. Existing installs
  that copied the old AgentHost folder keep whatever they copied, but nothing
  ships it or documents it anymore.
- **Wake-on-knock opens the app; it never starts a session.** The opt-in
  wake preference still works: when a tool call arrives and no session
  exists, the proxy can launch AutoCommand (one UAC approval) - but the app
  now opens normally at the Be My Guest tab and *you* click Start. A knock
  can bring the door to your face; only you can open it.
- **Honest guidance, everywhere.** The proxy's offline answers, the wake
  consent dialog, and the README all now say the same thing: start the
  session in the Be My Guest tab; MCP clients forward into the session you
  started and answer with setup guidance when none is running.
- **Why this removes the .NET runtime requirement:** the only framework-
  dependent component in the zip was AgentHost (published
  `--self-contained false` on purpose). AutoCommand.exe and AgentProxy.exe
  both ship self-contained. With AgentHost gone, a fresh Windows 11 machine
  needs nothing installed - not the SDK, not the runtime, ever.

## Notes

- The wire-protocol smoke test (test-agent-bridge.ps1) now attaches to a
  live session started from the Be My Guest tab instead of spawning a
  headless one.
- Allow-list tamper-evidence, surface verdicts and re-arm (v2026.11.3.1)
  are unchanged.
