# Microsoft Store Submission Guide for DeviceMonitorCS

## 1. Compliance Changes Actions (Completed)
We have moved writable files (`monitored_guids.txt`) to `%LocalAppData%`. This satisfies the requirement that apps cannot write to their installation directory.

## 2. Submission Method: "Win32 App"
Since this is an elevated (Administrator) application, the standard **Win32 App** submission path is the most appropriate. You do **not** need to convert it to UWP or a restricted MSIX container.

### How to Submit:
1.  **Package**: Zip your `publish/v2.5.1` folder (which you already have).
2.  **Installer**: ideally wrap your exe in a simple MSI or EXE installer (like InnoSetup), OR you can submit the "loose files" if you provide a URL to the EXE installer.
    *   *Simpler Option:* You can submit the purely "portable" zip if you host it yourself, but the Store prefers an Installer (MSI/EXE).
3.  **Partner Center**: Go to [Partner Center](https://partner.microsoft.com/dashboard).
4.  **Create App**: Reserve your name.
5.  **Submission**:
    - **Package URL**: You host the installer (e.g., on GitHub Releases) and provide the direct download link.
    - **Analyst Notes / Permissions**: This is where you explain the elevation.

## 3. Explaining Elevation (runFullTrust)
If you package as MSIX (optional but cleaner), you need `runFullTrust`. If you submit as a raw Win32 app (easiest), you just justify it in the form.

**Justification Text for Store Submission:**
> "This application is a System Utility designed to monitor low-level hardware events and security policies. It requires Administrator privileges (runFullTrust/Elevation) to:
> 1. Use the Windows Management Instrumentation (WMI) to detect generic hardware changes.
> 2. Read 'Microsoft-Windows-Windows Defender/Operational' event logs (requires Admin).
> 3. Enforce Firewall Rules using the 'NetFwTypeLib' API.
> 4. Query low-level network adapter status via P/Invoke.
> Without elevation, the core functionality of monitoring system-wide security events and hardware changes is impossible."

## 4. Declaring runFullTrust (If Packaging as MSIX)
If you decide to package as MSIX using the **Windows Application Packaging Project**:
1.  Open `Package.appxmanifest`.
2.  Go to **Capabilities**.
3.  Check **"Full Trust"** (this adds `runFullTrust`).
4.  In the manifest XML, add `<rescap:Capability Name="allowElevation" />` if targeting newer Windows versions, though standard `runFullTrust` often implies the ability to *ask* for elevation via the EXE manifest (which we already have via `app.manifest` `requireAdministrator`).

**Recommendation:** Start with the **Win32 App** submission pointing to your GitHub Release EXE installer. It's the path of least resistance for admin tools.
