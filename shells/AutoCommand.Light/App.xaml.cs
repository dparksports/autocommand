using System;
using System.Windows;

namespace AutoCommand.Light
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // UI-thread exceptions surface, log to Light's own data root,
            // and never take the app down — the same contract as Advanced.
            DispatcherUnhandledException += (s, args) =>
            {
                LogCrash(args.Exception, "Dispatcher");
                args.Handled = true;
                MessageBox.Show(
                    $"Something went wrong: {args.Exception.Message}\n\nDetails were saved to " +
                    System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "AutoCommandLight", "crash.log"),
                    "AutoCommand Light", MessageBoxButton.OK, MessageBoxImage.Error);
            };
            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                if (args.ExceptionObject is Exception ex) LogCrash(ex, "AppDomain");
            };
            System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, args) =>
            {
                LogCrash(args.Exception, "TaskScheduler");
                args.SetObserved();
            };

            // Order matters: engines learn Light's identity and the facade
            // seam is re-pointed BEFORE any of the facade-bound services
            // start — then every background watcher speaks AL-BLOCK and
            // writes into Light's own data root.
            LightServices.Initialize();

            // Ground-truth denial telemetry (WFP 5157 audit): rate-limited,
            // persisted under Light's root. Machine-global audit flip is
            // idempotent — safe whether or not the Advanced app also runs.
            FirewallDenyWatchService.Instance.Start();

            // The live "who is being blocked" feed, joined against the
            // AL+adopted-AC inventory. Degrades silently without Sysmon.
            BlockHitFeedService.Instance.Start();

            // Name-blocked apps stay blocked across moves/updates. Runs
            // without Sysmon (disk sweeps); never the last rule.
            AppBlockCoverageService.Instance.Start();

            // Domain blocks the user maintains; a no-op until the list is
            // non-empty, and the reconcile cadence rides the deny/feed
            // services' own timers in this shell.
            DomainBlockSyncService.Instance.Start();

            var window = new MainWindow();
            MainWindow = window;
            window.Show();

            // Connections start flowing immediately — the product promise
            // is "it is already watching", so the watcher starts with the
            // window, not on first click.
            LightServices.StartWatch();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            LightServices.Shutdown();
            base.OnExit(e);
        }

        private static void LogCrash(Exception ex, string source)
        {
            try
            {
                string dir = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "AutoCommandLight");
                System.IO.Directory.CreateDirectory(dir);
                string entry = $"\n[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{source}]\n{ex}\n";
                System.IO.File.AppendAllText(System.IO.Path.Combine(dir, "crash.log"), entry);
            }
            catch { // failsafe
            }
        }
    }
}
