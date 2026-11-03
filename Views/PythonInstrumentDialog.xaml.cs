using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using AutoCommand.Engines.Watch;
using AutoCommand.Forensics.Core;
using AutoCommand.Helpers;

namespace AutoCommand.Views
{
    /// <summary>
    /// Per-environment opt-in for the audit hook. Environments are discovered
    /// automatically from every source the installer service knows (registry,
    /// PATH, Store, conda, uv, pyenv-win, scoop/choco), a bounded background
    /// scan for venvs, and python images this machine has actually run (a
    /// transient Sysmon backfill — no live watcher is left behind).
    /// Auto-populating the list never installs anything — Instrument stays
    /// behind the confirmation, by design.
    /// </summary>
    public partial class PythonInstrumentDialog : Window
    {
        private readonly PyTraceInstallerService _installer = new();

        private readonly ObservableCollection<EnvRow> _rows = new();
        private readonly HashSet<string> _knownSitePackages = new(StringComparer.OrdinalIgnoreCase);
        private List<string> _excluded = new();

        private CancellationTokenSource _scanCts;

        /// <summary>Row view-model: checkbox state + instrumented flag + disable reason.</summary>
        private sealed class EnvRow
        {
            public PyTraceInstallerService.PythonEnv Env;
            public bool Checked;
            public bool Enabled => Env.CanInstrument;
            public string Display { get; set; }
            public string ToolTipText { get; set; }
            public string Reason => Env.DisableReason;
            public Visibility ReasonVisibility =>
                string.IsNullOrEmpty(Env.DisableReason) ? Visibility.Collapsed : Visibility.Visible;
        }

        public PythonInstrumentDialog()
        {
            InitializeComponent();
            WindowPlacement.ConstrainToMonitor(this);   // must fit an 800×600 screen
            EnvList.ItemsSource = _rows;
            Populate();
            _ = DiscoverSeenRunningAsync(); // tier 3 streams in after the fast tiers
        }

        // -----------------------------------------------------------------------
        // Population: tier 1 + manifest + tier 3 (seen running)
        // -----------------------------------------------------------------------

        private void Populate()
        {
            _rows.Clear();
            _knownSitePackages.Clear();
            _excluded = _installer.LoadScanState().Excluded;

            foreach (var env in _installer.DiscoverEnvironments())
                AddEnv(env);

            // Manifest entries no longer discovered (moved venvs etc.) keep an
            // Uninstall surface.
            foreach (var entry in _installer.LoadManifest())
            {
                if (_knownSitePackages.Contains(System.IO.Path.GetFullPath(entry.SitePackages))) continue;
                if (System.IO.Directory.Exists(entry.SitePackages))
                    AddEnv(new PyTraceInstallerService.PythonEnv
                    {
                        SitePackages = entry.SitePackages,
                        Root = entry.Root ?? entry.SitePackages,
                        Source = entry.Source ?? "manifest"
                    });
            }

            SortRows();
            UpdateStatus();
        }

        /// <summary>Adds one env to the list unless already known or excluded.</summary>
        private void AddEnv(PyTraceInstallerService.PythonEnv env)
        {
            if (env?.SitePackages == null) return;
            string key = System.IO.Path.GetFullPath(env.SitePackages);
            if (!_knownSitePackages.Add(key)) return;
            if (_excluded.Any(x => x.Equals(key, StringComparison.OrdinalIgnoreCase))) return;

            bool installed = _installer.IsInstalled(env.SitePackages);
            _rows.Add(new EnvRow
            {
                Env = env,
                Checked = installed && env.CanInstrument,
                Display = $"{(installed ? "[instrumented] " : env.CanInstrument ? "[plain]       " : "[unusable]    ")}{env.Display}",
                ToolTipText = $"site-packages: {env.SitePackages}{Environment.NewLine}source: {env.Source}" +
                              (env.DisableReason != null ? Environment.NewLine + env.DisableReason : "")
            });
        }

        /// <summary>
        /// Tier 3: python images this machine has actually run — replayed from
        /// the Sysmon archive through a transient spawn watcher (created,
        /// backfilled, stopped; nothing keeps watching).
        /// </summary>
        private async System.Threading.Tasks.Task DiscoverSeenRunningAsync()
        {
            try
            {
                var seen = await System.Threading.Tasks.Task.Run(() =>
                {
                    var watcher = new ImageSpawnWatcherService(
                        new Func<string, bool>(ImageSpawnWatcherService.IsPythonImage),
                        "python", venvPairing: true);
                    try
                    {
                        watcher.Backfill(TimeSpan.FromHours(6));
                        return watcher.GetSeenImages().ToList();
                    }
                    finally
                    {
                        watcher.Stop();
                    }
                });
                foreach (string image in seen)
                    AddEnv(PyTraceInstallerService.EnvFromImage(image));
                SortRows();
                UpdateStatus();
            }
            catch
            {
                // seen-running is a bonus tier — never fails the dialog
            }
        }

        private void SortRows()
        {
            var sorted = _rows
                .OrderBy(r => r.Env.CanInstrument ? 1 : 0)          // unusable rows sink
                .ThenBy(r => _installer.IsInstalled(r.Env.SitePackages) ? 0 : 1)
                .ThenBy(r => r.Env.Root, StringComparer.OrdinalIgnoreCase)
                .ToList();
            _rows.Clear();
            foreach (var row in sorted) _rows.Add(row);
        }

        private void UpdateStatus()
        {
            int instrumented = _rows.Count(r => _installer.IsInstalled(r.Env.SitePackages));
            int instrumentable = _rows.Count(r => r.Env.CanInstrument);
            StatusText.Text = $"{_rows.Count} environment(s) found · {instrumented} instrumented · {instrumentable} instrumentable";
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => Populate();

        // -----------------------------------------------------------------------
        // Deep scan (tier 2)
        // -----------------------------------------------------------------------

        private void DeepScanBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_scanCts != null)
            {
                _scanCts.Cancel(); // press again stops the scan
                return;
            }

            var roots = _installer.GetScanRoots();
            _scanCts = new CancellationTokenSource();
            DeepScanBtn.Content = "⏹ Stop scan";
            int found = 0;

            var cts = _scanCts;
            System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    PyTraceInstallerService.ScanForVenvs(roots, maxDepth: 6, maxDirectories: 100_000,
                        env => Dispatcher.Invoke(() => OnScanFound(env, cts, ref found)), cts.Token);
                }
                finally
                {
                    Dispatcher.Invoke(() =>
                    {
                        _installer.MarkScanned();
                        _scanCts = null;
                        DeepScanBtn.Content = "🔍 Deep scan for venvs";
                        SortRows();
                        UpdateStatus();
                        if (!cts.IsCancellationRequested)
                            StatusText.Text = $"Scan complete — {_rows.Count} environment(s) in the list. " +
                                              "Instrument all found, or pick and choose.";
                    });
                }
            });
        }

        private void OnScanFound(PyTraceInstallerService.PythonEnv env, CancellationTokenSource cts, ref int found)
        {
            if (env?.SitePackages == null) return;
            string key = System.IO.Path.GetFullPath(env.SitePackages);
            if (_knownSitePackages.Contains(key)) return;
            if (_excluded.Any(x => x.Equals(key, StringComparison.OrdinalIgnoreCase))) return;

            _knownSitePackages.Add(key);
            AddEnv(env);
            found++;
            StatusText.Text = $"Scanning… {found} new environment(s) found so far";
        }

        // -----------------------------------------------------------------------
        // Manual add / forget
        // -----------------------------------------------------------------------

        private void AddVenvBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title = "Pick the venv or python root folder (the one containing Lib\\site-packages)"
            };
            if (dialog.ShowDialog(this) != true) return;

            var env = _installer.EnvFromVenvRoot(dialog.FolderName) ??
                      PyTraceInstallerService.EnvFromExeDir(dialog.FolderName, "manual");
            if (env == null)
            {
                MessageBox.Show(this,
                    $"No Lib\\site-packages found under:\n{dialog.FolderName}\n\nPick the environment's root folder itself, not site-packages.",
                    "Not a python environment", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (_knownSitePackages.Contains(System.IO.Path.GetFullPath(env.SitePackages)))
            {
                MessageBox.Show(this, "That environment is already in the list.", "Already listed",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            _installer.AddScanRoot(dialog.FolderName); // future deep scans include it
            AddEnv(env);
            SortRows();
            UpdateStatus();
        }

        private void ForgetBtn_Click(object sender, RoutedEventArgs e)
        {
            var selected = _rows.Where(r => r.Checked).ToList();
            if (selected.Count == 0)
            {
                MessageBox.Show(this, "Check the environment(s) to forget first.",
                    "Nothing selected", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            foreach (var row in selected)
            {
                // Keep manifest entries forgettable too, but warn if instrumented
                if (_installer.IsInstalled(row.Env.SitePackages))
                {
                    var answer = MessageBox.Show(this,
                        $"'{row.Env.Root}' is instrumented. Forget it anyway (leaves the hook installed)?\n" +
                        "Use 'Remove selected' first to uninstall cleanly.",
                        "Instrumented", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                    if (answer != MessageBoxResult.Yes) continue;
                }
                _installer.ExcludeSitePackages(row.Env.SitePackages);
            }
            Populate();
        }

        // -----------------------------------------------------------------------
        // Install / uninstall — always behind the explicit confirmation
        // -----------------------------------------------------------------------

        private void InstallBtn_Click(object sender, RoutedEventArgs e) => ApplyToChecked(install: true);

        private void UninstallBtn_Click(object sender, RoutedEventArgs e) => ApplyToChecked(install: false);

        private void InstrumentAllBtn_Click(object sender, RoutedEventArgs e)
        {
            var targets = _rows.Where(r => r.Env.CanInstrument).ToList();
            if (targets.Count == 0)
            {
                MessageBox.Show(this, "No instrumentable environments in the list — run Rediscover or Deep scan first.",
                    "Nothing to instrument", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            foreach (var row in targets) row.Checked = true;
            EnvList.Items.Refresh();
            ApplyToChecked(install: true);
        }

        private void ApplyToChecked(bool install)
        {
            var selected = _rows.Where(r => r.Checked && r.Env.CanInstrument).ToList();
            if (selected.Count == 0)
            {
                MessageBox.Show(this, "Check at least one instrumentable environment first.",
                    "Nothing selected", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (install)
            {
                string machineWide = selected.Any(r => IsMachineWide(r.Env))
                    ? "\n⚠ Machine-wide environment(s) in the selection — every user of this python gets instrumented."
                    : "";
                var confirm = MessageBox.Show(this,
                    $"Instrument {selected.Count} environment(s)?\n\n" +
                    "Writes two small files into each site-packages (PyTraceHook_ac.py + PyTraceHook_ac.pth):\n" +
                    "· every python from those environments records the Python stack when it spawns processes\n" +
                    "· every python from those environments logs TLS session keys to a user-only-ACL file\n" +
                    "   (AutoCommand\\pytrace\\sslkeys.log) so its own HTTPS traffic can be decrypted in-tab\n\n" +
                    "This is visible instrumentation — anyone reading those files knows they exist.\n" +
                    "Remove anytime from this dialog." + machineWide,
                    "Instrument environments", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (confirm != MessageBoxResult.Yes) return;
            }

            int done = 0;
            var errors = new List<string>();
            foreach (var row in selected)
            {
                string error = install ? _installer.Install(row.Env) : _installer.Uninstall(row.Env.SitePackages);
                if (error == null) done++;
                else errors.Add($"{row.Env.Root}: {error}");
            }

            Populate();
            StatusText.Text = errors.Count > 0
                ? $"{done} succeeded, {errors.Count} failed:\n{string.Join("\n", errors)}"
                : $"{done} environment(s) {(install ? "instrumented" : "cleaned")}.";
        }

        /// <summary>Program Files installs are shared by every user of the machine.</summary>
        private static bool IsMachineWide(PyTraceInstallerService.PythonEnv env) =>
            env.SitePackages.StartsWith(@"C:\Program Files", StringComparison.OrdinalIgnoreCase);
    }
}
