namespace ShieldsUp.Core;

/// <summary>
/// Single anchor for ShieldsUp's on-disk state. AutoCommand kept state in the app directory
/// and under ProgramData\AutoCommand; ShieldsUp namespaces everything under ProgramData\ShieldsUp
/// with the same file names and formats so the knowledge carries over.
/// </summary>
public static class AppPaths
{
    public const string AppName = "ShieldsUp";

    public static string DataRoot { get; private set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AppName);

    /// <summary>
    /// Host-app seam (the same "one engine, many faces" pattern as
    /// Engines.Core Identity): a host that vendors this core points the data
    /// root at its own machine folder BEFORE any service constructs —
    /// FirewallConfigManager captures its path at first use. AutoCommand's
    /// tab passes %PROGRAMDATA%\AutoCommand, where the file names already
    /// match by design, so firewall_config.json becomes one desired-state
    /// store both apps' enforcers read.
    /// </summary>
    public static void Configure(string dataRoot)
    {
        DataRoot = dataRoot;
        AutoCommand.Contain.Core.FirewallConfigManager.DefaultConfigPath = FirewallConfigPath;
        AutoCommand.Contain.Core.FirewallConfigManager.Instance.Load();
    }

    public static string BloatwareConfigPath => Path.Combine(DataRoot, "bloatware_config.json");
    public static string FirewallConfigPath => Path.Combine(DataRoot, "firewall_config.json");
    public static string TelemetryStatePath => Path.Combine(DataRoot, "telemetry_state.json");
    public static string NameResolutionStatePath => Path.Combine(DataRoot, "name-resolution-doors.json");
    public static string EfiBaselinePath => Path.Combine(DataRoot, "efi_baseline.json");

    public static string CrashLogPath => Path.Combine(AppContext.BaseDirectory, "crash.log");

    public static void EnsureDataRoot()
    {
        Directory.CreateDirectory(DataRoot);
    }
}
