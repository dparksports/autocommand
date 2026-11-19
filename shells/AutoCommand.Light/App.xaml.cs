using System;
using System.Windows;
using System.Windows.Threading;

namespace AutoCommand.Light
{
    public partial class App : Application
    {
        private TrayController? _tray;
        private readonly DispatcherTimer _sweep = new(DispatcherPriority.Background)
        { Interval = TimeSpan.FromSeconds(15) };

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // UI-thread exceptions surface, log to Light's own data root,
            // and never take the gate down — same contract as Advanced.
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
            // seam is re-pointed BEFORE any facade-bound service starts —
            // then every watcher speaks AL-BLOCK and writes Light's root.
            LightServices.Initialize();
            LightGate.Initialize();

            // Kernel-side denial telemetry (WFP 5157 audit): the ground
            // truth the gate's "attempts stopped" numbers rest on.
            FirewallDenyWatchService.Instance.Start();

            // The live "who is being blocked" feed — joined against the
            // AL + adopted-AC inventory. Degrades silently without Sysmon.
            BlockHitFeedService.Instance.Start();

            // Name-blocked apps stay blocked across moves/updates — the
            // gate's rules survive app updates because of this service.
            AppBlockCoverageService.Instance.Start();

            // Domain blocks (sync service no-ops until a list exists).
            DomainBlockSyncService.Instance.Start();

            var window = new MainWindow();
            MainWindow = window;
            window.Show();

            LightServices.StartWatch();

            // the tray is the persistent surface: states without the window
            _tray = new TrayController(
                readState: () =>
                {
                    var asks = LightGate.PendingAsks().Count;
                    var attempts = LightGate.AttemptsToday().Count;
                    var state = asks > 0 ? TrayController.TrayState.Asking
                        : attempts > 0 ? TrayController.TrayState.Stopped
                        : TrayController.TrayState.Quiet;
                    var tooltip = state switch
                    {
                        TrayController.TrayState.Asking => $"{asks} app(s) waiting for your answer",
                        TrayController.TrayState.Stopped => $"{attempts} attempt(s) stopped today",
                        _ => "AutoCommand Light — quiet",
                    };
                    return (tooltip, state);
                },
                openToday: () => (MainWindow as MainWindow)?.NavigateTo("today"),
                openApps: () => { (MainWindow as MainWindow)?.ShowFromTray(); (MainWindow as MainWindow)?.NavigateTo("apps"); },
                openTemporarily: () => _ = LightGate.OpenForEveryoneAsync(TimeSpan.FromMinutes(10)),
                quit: () => Shutdown());

            // the enforcement tick: expire allow-once, resolve running
            // apps, decide expired tickets — everything but first-attempt
            // ensures, which happen synchronously in the event stream
            LightGate.Changed += () => Dispatcher.BeginInvoke(new Action(() =>
                _tray?.UpdateFrom(LightGate.PendingAsks().Count, LightGate.AttemptsToday().Count)));
            _sweep.Tick += (s, e) => _ = LightGate.SweepAsync();
            _sweep.Start();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            _sweep.Stop();
            _tray?.Dispose();
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
