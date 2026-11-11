using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using AutoCommand.Matrix;

namespace RainSelfTest
{
    /// <summary>Synthetic rain feed: three fake PIDs — one busy transmitter,
    /// one slow, one blocked-but-retrying — no engines, no admin. Rebuilds
    /// a NEW snapshot list every tick, like the real feed: the renderer
    /// gates on snapshot-list identity, so mutating one list in place would
    /// (correctly) never be consumed.</summary>
    internal sealed class SynthFeed
    {
        private readonly DispatcherTimer _t;
        private long _busyTx, _slowTx;
        private int _tick;
        private int _blockedAttempts;

        public IReadOnlyList<PidSnapshot> Latest { get; private set; } =
            new List<PidSnapshot>();

        public SynthFeed()
        {
            _t = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
            _t.Tick += (s, e) =>
            {
                _tick++;
                _busyTx += 2 + (_tick % 5);              // steady stream
                if (_tick % 7 == 0) _slowTx += 1;        // occasional
                _blockedAttempts = (_tick % 20 == 0) ? 1 : 0;  // retry pulse
                Latest = new List<PidSnapshot>
                {
                    new PidSnapshot { Pid = 2044, Name = "busy.exe",   TxPackets = _busyTx, TxBytes = _busyTx * 400, Connections = 2 },
                    new PidSnapshot { Pid = 4070, Name = "slow.exe",   TxPackets = _slowTx, Connections = 1 },
                    new PidSnapshot { Pid = 9021, Name = "blocked.exe", Blocked = true, Attempts = _blockedAttempts, Connections = 1 },
                };
            };
        }

        public void Start() => _t.Start();
        public void Stop() => _t.Stop();
    }

    internal sealed class RainTabStub : UserControl
    {
        private MatrixRenderer _renderer;
        private SynthFeed _feed;
        private MatrixRainConfig _cfg;
        private readonly TextBlock _diag = new()
        {
            FontFamily = new FontFamily("Consolas"),
            FontSize = 22,
            Foreground = Brushes.White,
            Margin = new Thickness(12, 0, 0, 24),
            VerticalAlignment = VerticalAlignment.Bottom,
            IsHitTestVisible = false
        };

        public RainTabStub()
        {
            var logPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "rainselftest.log");
            var grid = new Grid { Background = new SolidColorBrush(Color.FromRgb(5, 8, 7)) };
            var ambient = new Image();
            var rain = new Image();
            grid.Children.Add(ambient);
            grid.Children.Add(rain);
            grid.Children.Add(_diag);
            Content = grid;

            // the exact wiring the real Rain tab uses — INCLUDING the
            // re-attach guard: a re-Load (every tab return) must reuse the
            // existing renderer and restart it via ApplyVisibility, never
            // early-return and leave it stopped
            Loaded += (s, e) =>
            {
                if (_renderer == null)
                {
                    _cfg = MatrixRainConfig.LoadOrDefault();
                    _cfg.Style = "cinema";   // self-test the movie look
                    _feed = new SynthFeed();
                    _renderer = new MatrixRenderer(ambient, rain, () => _feed.Latest, _cfg);
                    _renderer.ActiveColumnsChanged += () =>
                        System.IO.File.AppendAllText(logPath,
                            $"[{DateTime.Now:HH:mm:ss.fff}] activeCols -> {_renderer.ActiveColumns}\n");
                    _renderer.SetSurfaceSize(ActualWidth, ActualHeight);
                }
                ApplyVisibility();
            };
            IsVisibleChanged += (s, e) => ApplyVisibility();
            SizeChanged += (s, e) => _renderer?.SetSurfaceSize(ActualWidth, ActualHeight);
            Unloaded += (s, e) => { _renderer?.Stop(); _feed?.Stop(); };

            var diag = new DispatcherTimer(System.Windows.Threading.DispatcherPriority.Render)
                { Interval = TimeSpan.FromMilliseconds(500) };
            int dumpCount = 0;
            System.IO.File.WriteAllText(logPath, $"=== run {DateTime.Now:HH:mm:ss.fff} ===\n");
            diag.Tick += (s, e) =>
            {
                var state = _renderer == null
                    ? "attaching (renderer null)"
                    : $"cols={_renderer.LiveColumns} draws={_renderer.DebugDraws} fps={_renderer.LastFps:0} visible={IsVisible} loaded={IsLoaded} inTree={(Window.GetWindow(this) != null)}";
                System.IO.File.AppendAllText(logPath, $"[{DateTime.Now:HH:mm:ss.fff}] {state}\n");
                if (_renderer == null) { _diag.Text = "attaching..."; return; }
                _diag.Text = $"synthetic feed · {_renderer.LiveColumns} columns · {_renderer.LastFps:0} fps";
                if (Window.GetWindow(this) is Window w)
                    w.Title = $"cols={_renderer.LiveColumns} fps={_renderer.LastFps:0} " +
                              $"draws={_renderer.DebugDraws} drops={_renderer.DebugDrops} budget={_renderer.DebugBudget:0} " +
                              $"surface={_renderer.SurfaceWidth}x{_renderer.SurfaceHeight}";
                // every ~4s, snapshot the rain surface for offline inspection
                if (++dumpCount % 8 == 0)
                    _renderer.DumpRainPng(System.IO.Path.Combine(
                        System.IO.Path.GetTempPath(), "rain_dump.png"));
            };
            diag.Start();
        }

        private void ApplyVisibility()
        {
            if (_renderer == null) return;
            if (IsVisible && IsLoaded) { _feed.Start(); _renderer.SetSurfaceSize(ActualWidth, ActualHeight); _renderer.Start(); }
            else { _renderer.Stop(); _feed.Stop(); }
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            var app = new Application();
            var tabs = new TabControl();
            var gridTab = new TabItem { Header = "grid (dummy)" };
            gridTab.Content = new Button { Content = "placeholder for the Process Monitor" };
            var rainTab = new TabItem { Header = "rain" };
            rainTab.Content = new RainTabStub();
            tabs.Items.Add(gridTab);
            tabs.Items.Add(rainTab);
            tabs.SelectedIndex = 0;   // start elsewhere, select rain later — the real timing

            var win = new Window
            {
                Title = "Rain self-test — synthetic feed",
                Width = 520,
                Height = 860,
                Left = 80,
                Top = 60,
                WindowStartupLocation = WindowStartupLocation.Manual,
                Content = tabs
            };

            var log = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "rainselftest.log");
            app.DispatcherUnhandledException += (s, e2) =>
            {
                System.IO.File.AppendAllText(log, $"!!! DISPATCHER EX: {e2.Exception}\n");
                e2.Handled = true;
            };
            AppDomain.CurrentDomain.UnhandledException += (s, e2) =>
                System.IO.File.AppendAllText(log, $"!!! APPDOMAIN EX: {e2.ExceptionObject}\n");
            win.Loaded += (s, e2) => System.IO.File.AppendAllText(log, $"[win] loaded\n");

            var select = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
            select.Tick += (s, e) => { select.Stop(); tabs.SelectedIndex = 1; };
            select.Start();

            // The real tab strip sends the user AWAY and back — every return
            // must re-start the renderer (Unloaded stopped it). The title's
            // fps readout after the round-trip is the regression signal.
            var away = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            away.Tick += (s, e) => { away.Stop(); tabs.SelectedIndex = 0; };
            away.Start();
            var back = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
            back.Tick += (s, e) => { back.Stop(); tabs.SelectedIndex = 1; };
            back.Start();

            app.Run(win);
        }
    }
}
