### Changes in v3.15.2
- **Defender**: Fixed Tamper Protection state detection when locally managed (registry bitmask `5`).
- **PowerShell Execution**: Added `-NoProfile` and `-NonInteractive` flags to suppress profile warning contamination.
- **Build**: Added conditional check for optional `sigcheck64.exe` dependency in `.csproj`.
