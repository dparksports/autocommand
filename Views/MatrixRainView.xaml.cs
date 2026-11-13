using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using AutoCommand.Matrix;

namespace AutoCommand.Views
{
    /// <summary>
    /// The Rain tab — the same engine as the standalone Matrix edition
    /// (dparksports/autocommand-matrix, since retired with its code folded
    /// in here), embedded as a face of the app: it renders the LIVE Process Monitor table (no engines of
    /// its own) for users who'd rather watch the animation than read the
    /// grid. Rendering pauses whenever the tab is hidden.
    ///
    /// Right-click = the animation menu (the tray menu's in-tab twin):
    /// fall speed, PID labels, receives, bloom, backdrop, charset, zLift,
    /// wake length, font size, diagnostics, and the config file itself —
    /// every change is saved to matrix_rain.json and hot-applied.
    /// </summary>
    public partial class MatrixRainView : UserControl
    {
        private MatrixRainConfig _cfg;
        private MatrixRainFeed _feed;
        private MatrixRenderer _renderer;
        private bool _attaching;
        private bool _diagVisible = true;

        // Render priority, not Background: under a loaded machine Background
        // work starves indefinitely and the strip freezes mid-sentence even
        // while the rain itself is fine — it costs two string writes/500ms.
        private readonly System.Windows.Threading.DispatcherTimer _diagTimer =
            new(System.Windows.Threading.DispatcherPriority.Render)
            {
                Interval = TimeSpan.FromMilliseconds(500)
            };

        public MatrixRainView()
        {
            InitializeComponent();
            BuildMenu();

            Loaded += (s, e) => Attach();
            IsVisibleChanged += (s, e) => ApplyVisibility();
            SizeChanged += (s, e) => _renderer?.SetSurfaceSize(ActualWidth, ActualHeight);
            Unloaded += (s, e) => { _renderer?.Stop(); _feed?.Stop(); };

            _diagTimer.Tick += (s, e) => UpdateDiag();
        }

        /// <summary>Wire up against the Process Monitor's live table. Both
        /// views are constructed at startup, but be resilient anyway: retry
        /// briefly if the monitor view has not registered yet. Anything that
        /// throws lands IN the strip — a silent "attaching..." is exactly
        /// how the first cut hid its failure.</summary>
        private void Attach()
        {
            if (!IsVisible) return;
            if (_renderer != null)
            {
                // Re-connected to the tree (every return to the tab after a
                // WPF TabControl unload): Unloaded stopped the renderer, and
                // IsVisibleChanged already fired while IsLoaded was still
                // false — so THIS is the only hook left that can restart it.
                ApplyVisibility();
                return;
            }
            if (_attaching) return;
            _attaching = true;

            var tracked = SvchostMonitorView.Current?.TrackedTable;
            if (tracked == null)
            {
                // Monitor view not registered yet — retry shortly, and say so.
                _attachRetries++;
                DiagText.Text = $"rain: attaching (waiting for the Process Monitor, try {_attachRetries})...";
                _attaching = false;
                var retry = new System.Windows.Threading.DispatcherTimer
                {
                    Interval = TimeSpan.FromMilliseconds(500)
                };
                retry.Tick += (s2, e2) => { retry.Stop(); Attach(); };
                retry.Start();
                return;
            }

            try
            {
                _cfg = MatrixRainConfig.LoadOrDefault();
                _feed = new MatrixRainFeed(tracked);
                _renderer = new MatrixRenderer(RainCanvas, () => _feed.Latest, _cfg);
                _renderer.ActiveColumnsChanged += ApplyColumnWidth;
                ApplyColumnWidth();
                _renderer.SetSurfaceSize(ActualWidth, ActualHeight);
            }
            catch (Exception ex)
            {
                DiagText.Text = "rain: attach failed — " + ex.Message +
                                "  (see Debug output for the full trace)";
                Debug.WriteLine("RainTab attach failed: " + ex);
                _attaching = false;
                return;
            }
            _attaching = false;

            ApplyVisibility();
        }

        private int _attachRetries;

        /// <summary>Raised (UI thread) when the pane's desired width
        /// changes — the host owns the actual Grid column and decides
        /// whether to honor it (auto-fit) or keep a user-dragged width.</summary>
        public event Action ColumnWidthChanged;

        /// <summary>Desired pane width in DIP: the alive, capped columns ×
        /// the cell width (minimum one column, so 0 alive keeps a sliver of
        /// presence). The +0.02 survives the device-px floor in the
        /// renderer's grid math.</summary>
        public double DesiredWidthDip => _renderer == null ? 0
            : Math.Max(_renderer.CellWidthDip, _renderer.ActiveColumns * _renderer.CellWidthDip + 0.02);

        private void ApplyColumnWidth()
        {
            if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(ApplyColumnWidth); return; }
            ColumnWidthChanged?.Invoke();
        }

        /// <summary>Render only while the tab is on screen — a hidden tab
        /// costs nothing.</summary>
        private void ApplyVisibility()
        {
            if (_renderer == null)
            {
                if (IsVisible && IsLoaded) Attach();
                return;
            }
            if (IsVisible && IsLoaded)
            {
                _feed?.Start();
                _renderer.SetSurfaceSize(ActualWidth, ActualHeight);
                _renderer.Start();
                _diagTimer.Start();
            }
            else
            {
                _renderer.Stop();
                _feed?.Stop();
                _diagTimer.Stop();
            }
        }

        // ------------------------------------------------------------------
        // Diagnostics — the strip tells you WHY if the pane looks still:
        // rows arriving, PIDs seen, columns allocated, live frame rate.
        // ------------------------------------------------------------------

        private void UpdateDiag()
        {
            if (_feed == null || _renderer == null) return;
            if (!_diagVisible) { DiagText.Text = ""; return; }

            if (_feed.LastConversationCount == 0)
            {
                DiagText.Text = "rain: no conversations yet — waiting for the Process Monitor's rows (Sysmon events, or its baseline snapshot)";
                return;
            }
            DiagText.Text =
                $"{_feed.LastConversationCount} conversations · {_feed.LastPidCount} pids · " +
                $"{_renderer.LiveColumns} columns · {_renderer.LastFps:0} fps" +
                "   (right-click to configure)";
        }

        // ------------------------------------------------------------------
        // The animation menu — the tray menu's in-tab twin
        // ------------------------------------------------------------------

        private MenuItem _speedItem;
        private MenuItem _labelsItem, _rxItem, _bloomItem, _ambientItem, _diagItem, _styleItem;
        private MenuItem _charsetMenu, _zLiftMenu;

        private void BuildMenu()
        {
            var menu = new ContextMenu();

            _speedItem = Header("Fall speed");
            menu.Items.Add(_speedItem);
            menu.Items.Add(Item("Fall slower", () => Mutate(c =>
                c.FallRowsPerSecond = Math.Max(5, Math.Round(c.FallRowsPerSecond * 0.75, 1)))));
            menu.Items.Add(Item("Fall faster", () => Mutate(c =>
                c.FallRowsPerSecond = Math.Min(200, Math.Round(c.FallRowsPerSecond * 4.0 / 3.0, 1)))));
            menu.Items.Add(new Separator());

            _labelsItem = Check("PID labels", () => Mutate(c => c.ShowLabels = !c.ShowLabels));
            _rxItem = Check("Rain on receives too", () => Mutate(c => c.RxMode = !c.RxMode));
            _bloomItem = Check("Bloom on the lead", () => Mutate(c => c.Bloom = !c.Bloom));
            _ambientItem = Check("Frozen backdrop", () => Mutate(c => c.Ambient = !c.Ambient));
            _diagItem = Check("Diagnostics strip", () => { _diagVisible = !_diagVisible; UpdateDiag(); });
            _styleItem = Check("Movie look (cinema)", () => Mutate(c =>
                c.Style = c.Style == "cinema" ? "instrument" : "cinema"));
            menu.Items.Add(_styleItem);
            menu.Items.Add(new Separator());
            menu.Items.Add(_labelsItem);
            menu.Items.Add(_rxItem);
            menu.Items.Add(_bloomItem);
            menu.Items.Add(_ambientItem);
            menu.Items.Add(_diagItem);
            menu.Items.Add(new Separator());

            _charsetMenu = Header("Glyph set");
            AddRadio(_charsetMenu, "katakana (alien)", "katakana");
            AddRadio(_charsetMenu, "katakana + latin", "katakana-latin");
            AddRadio(_charsetMenu, "latin", "latin");
            AddRadio(_charsetMenu, "digits", "digits");
            menu.Items.Add(_charsetMenu);

            _zLiftMenu = Header("Lead elevation (zLift)");
            AddRadio(_zLiftMenu, "flat (1.0)", "1.0");
            AddRadio(_zLiftMenu, "subtle (1.06)", "1.06");
            AddRadio(_zLiftMenu, "lifted (1.3)", "1.3");
            AddRadio(_zLiftMenu, "dramatic (1.5)", "1.5");
            menu.Items.Add(_zLiftMenu);

            menu.Items.Add(Item("Wake shorter", () => Mutate(c =>
                c.WakeFadeSeconds = Math.Max(0.3, Math.Round(c.WakeFadeSeconds * 0.75, 2)))));
            menu.Items.Add(Item("Wake longer", () => Mutate(c =>
                c.WakeFadeSeconds = Math.Min(10, Math.Round(c.WakeFadeSeconds * 4.0 / 3.0, 2)))));
            menu.Items.Add(new Separator());

            menu.Items.Add(Item("Glyph size smaller", () => Mutate(c =>
                c.FontSizePx = Math.Max(9, c.FontSizePx - 2))));
            menu.Items.Add(Item("Glyph size larger", () => Mutate(c =>
                c.FontSizePx = Math.Min(48, c.FontSizePx + 2))));
            menu.Items.Add(new Separator());

            menu.Items.Add(Item("Edit matrix_rain.json", () => Process.Start(new ProcessStartInfo(
                "notepad.exe", MatrixRainConfig.ConfigPath) { UseShellExecute = true })));
            menu.Items.Add(Item("Reload config", () =>
            {
                _cfg = MatrixRainConfig.LoadOrDefault();
                _renderer?.ApplyConfig(_cfg);
            }));
            menu.Items.Add(Item("Reset style to defaults", () =>
            {
                var fresh = new MatrixRainConfig();
                fresh.Normalize();
                _cfg = fresh;
                MatrixRainConfig.Save(_cfg);
                _renderer?.ApplyConfig(_cfg);
            }));

            ContextMenu = menu;
        }

        private void OnContextMenuOpening(object sender, ContextMenuEventArgs e) => SyncMenu();

        private void SyncMenu()
        {
            if (_cfg == null) return;
            _speedItem.Header = $"Fall speed: {_cfg.FallRowsPerSecond:0.#} rows/s";
            _labelsItem.IsChecked = _cfg.ShowLabels;
            _rxItem.IsChecked = _cfg.RxMode;
            _bloomItem.IsChecked = _cfg.Bloom;
            _ambientItem.IsChecked = _cfg.Ambient;
            _diagItem.IsChecked = _diagVisible;
            _styleItem.IsChecked = _cfg.Style == "cinema";
            SyncRadios(_charsetMenu, _cfg.Charset);
            SyncRadios(_zLiftMenu, _cfg.ZLift.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture));
        }

        private void Mutate(Action<MatrixRainConfig> change)
        {
            if (_cfg == null) return;
            change(_cfg);
            MatrixRainConfig.Save(_cfg);
            _renderer?.ApplyConfig(_cfg);
        }

        private MenuItem Header(string text) => new() { Header = text, IsEnabled = false };

        private MenuItem Item(string text, Action onClick) =>
            new() { Header = text, Command = new RelayCommand(onClick) };

        private MenuItem Check(string text, Action onClick) =>
            new() { Header = text, IsCheckable = true, Command = new RelayCommand(onClick) };

        private void AddRadio(MenuItem parent, string text, string value)
        {
            parent.Items.Add(new MenuItem
            {
                Header = text,
                IsCheckable = true,
                Command = new RelayCommand(() => Mutate(c =>
                {
                    if (parent == _charsetMenu) c.Charset = value;
                    else c.ZLift = double.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
                })),
                Tag = value
            });
        }

        private static void SyncRadios(MenuItem parent, string active)
        {
            foreach (var child in parent.Items)
                if (child is MenuItem mi && mi.Tag is string tag)
                    mi.IsChecked = string.Equals(tag, active, StringComparison.OrdinalIgnoreCase);
        }

        private sealed class RelayCommand : System.Windows.Input.ICommand
        {
            private readonly Action _run;
            public RelayCommand(Action run) => _run = run;
            public event EventHandler CanExecuteChanged { add { } remove { } }
            public bool CanExecute(object parameter) => true;
            public void Execute(object parameter) => _run();
        }
    }
}
