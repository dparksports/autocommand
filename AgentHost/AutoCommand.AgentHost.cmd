@echo off
rem AutoCommand AgentHost launcher.
rem
rem Fast path: when a .NET 10 runtime is available, run the framework-dependent
rem exe directly - it boots in milliseconds, which is the point of this tool.
rem DOTNET_ROOT is pointed at the same dotnet the probe validated, so portable
rem dotnet installs (PATH-only, no registry) resolve too. An existing
rem DOTNET_ROOT set by the caller is respected, not overwritten.
rem
rem Fallback: on a machine without .NET 10, reuse the runtime embedded in the
rem app itself - AutoCommand.exe ships self-contained and carries its own
rem headless agent path (--agent-headless) with the same session semantics:
rem same bridge, same tools, mutating tools denied, single-instance guard.
rem
rem Usage: AutoCommand.AgentHost.cmd [seconds]
rem   Both paths accept an optional auto-stop after N seconds; omit it to run
rem   until stdin closes or Ctrl+C.
rem
rem Note for scripts that export their own DOTNET_ROOT (some MCP clients do):
rem a stale DOTNET_ROOT pointing at an older runtime wins over the probe - the
rem exe would then fail with the "You must install .NET" dialog. Clear the
rem variable for AutoCommand sessions, or call the exe/app paths directly.

rem Probe: any .NET 10 runtime anywhere reachable via PATH?
dotnet --list-runtimes 2>nul | findstr /c:"Microsoft.NETCore.App 10." >nul
if errorlevel 1 goto embedded

rem Same-runtime guarantee: aim the apphost at the dotnet the probe just used
rem (first PATH hit), unless the caller already chose a DOTNET_ROOT.
for /f "delims=" %%D in ('where dotnet 2^>nul') do if not defined DOTNET_ROOT set "DOTNET_ROOT=%%~dpD"

"%~dp0AutoCommand.AgentHost.exe" %*
exit /b %errorlevel%

:embedded
"%~dp0..\AutoCommand.exe" --agent-headless %~1
exit /b %errorlevel%
