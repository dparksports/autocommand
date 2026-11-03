using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace AutoCommand.Helpers
{
    /// <summary>
    /// Adaptive window placement: AutoCommand must be usable on the screens a
    /// refresh install of Windows actually shows — an 800×600 panel on the
    /// Basic Display Adapter until GPU drivers land is the floor (Windows'
    /// official minimum) — while larger displays keep the designed 1200×750.
    ///
    /// The rules, applied at startup before the window is shown:
    ///   · persisted geometry is restored when it fits the CURRENT work area
    ///     (clamped, so a resolution jump after driver install self-corrects);
    ///   · otherwise, screens too small for the design size breathe by
    ///     starting MAXIMIZED — title bar and every pane reachable;
    ///   · otherwise the design size centers, as before.
    ///
    /// Dialogs use <see cref="ConstrainToMonitor"/> instead: they can never
    /// open larger than the monitor they appear on, and their MinWidth floors
    /// (ConnectionPeek demands 880px, BlockedRules 760, ProcessTrace 720 —
    /// all wider than 800) are lowered to match, because a floor wider than
    /// the screen is a window that permanently clips.
    ///
    /// State persists as five lines in window_state.txt — state, W, H, X, Y —
    /// the same %LOCALAPPDATA%\AutoCommand home and plain-text idiom as
    /// rain_panel.txt. QA can fake a small screen on a dev box with
    /// AUTOCOMMAND_FORCE_WORKAREA=800x600 (panel size; a nominal taskbar is
    /// subtracted) without a test bench.
    /// </summary>
    public static class WindowPlacement
    {
        // ── design size & floors ─────────────────────────────────────────
        // Design size mirrors MainWindow.xaml's Width/Height. The floors are
        // deliberately BELOW 800×600: the work area is smaller than the panel
        // (the taskbar takes ~48px) and 125% scaling on a tiny panel gives an
        // effective 640×480 desktop. The resize floor must fit inside that.
        public const double DesignWidth = 1200;
        public const double DesignHeight = 750;
        public const double MinWidth = 640;
        public const double MinHeight = 420;

        // breathing margin before "the design size doesn't really fit" tips
        // into maximized — a bare 2px fit rides the taskbar edge
        private const double FitMargin = 24;
        private const double NominalTaskbarHeight = 48;

        private static bool _smallScreenStartup;

        /// <summary>True when this launch took the small-screen (maximized) path.</summary>
        public static bool SmallScreenStartup => _smallScreenStartup;

        private static string StatePath => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand", "window_state.txt");

        // ── work area: per-monitor, in DIPs ──────────────────────────────
        // SystemParameters.WorkArea is the PRIMARY monitor only. A window
        // (or a dialog about to open) may live on another monitor, so the
        // real lookup goes through MonitorFromWindow; the rectangle comes
        // back in that monitor's physical pixels and is scaled to DIPs with
        // the window's current DPI (correct under PerMonitorV2). The primary
        // work area remains the fallback while a window has no HWND yet —
        // CenterScreen targets the primary anyway.

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT { public int Left, Top, Right, Bottom; }

        [StructLayout(LayoutKind.Sequential)]
        private struct MONITORINFO
        {
            public int cbSize;
            public RECT rcMonitor;
            public RECT rcWork;
            public uint dwFlags;
        }

        [DllImport("user32.dll")]
        private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint nFlags);

        [DllImport("user32.dll")]
        private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO info);

        private const uint MONITOR_DEFAULTTONEAREST = 2;

        /// <summary>The work area (screen minus taskbar) of the monitor the window will appear on, in DIPs.</summary>
        public static Rect WorkAreaOf(Window window)
        {
            // QA hook: simulate a small panel without a test bench. Format
            // "WIDTHxHEIGHT" in physical pixels; a nominal taskbar is
            // subtracted so the simulated work area matches a real install.
            var forced = Environment.GetEnvironmentVariable("AUTOCOMMAND_FORCE_WORKAREA");
            if (!string.IsNullOrWhiteSpace(forced))
            {
                int x = forced.IndexOf('x');
                if (x > 0
                    && double.TryParse(forced.AsSpan(0, x), System.Globalization.NumberStyles.Float,
                        System.Globalization.CultureInfo.InvariantCulture, out var w)
                    && double.TryParse(forced.AsSpan(x + 1), System.Globalization.NumberStyles.Float,
                        System.Globalization.CultureInfo.InvariantCulture, out var h)
                    && w >= 320 && h >= 240)
                {
                    return new Rect(0, 0, w, Math.Max(240, h - NominalTaskbarHeight));
                }
            }

            var hwnd = window == null ? IntPtr.Zero : new WindowInteropHelper(window).Handle;
            if (hwnd != IntPtr.Zero)
            {
                var mi = new MONITORINFO { cbSize = Marshal.SizeOf(typeof(MONITORINFO)) };
                if (GetMonitorInfo(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), ref mi))
                {
                    double dpi = PresentationSource.FromVisual(window)?.CompositionTarget
                                     ?.TransformToDevice.M11 ?? 1.0;
                    if (dpi <= 0) dpi = 1.0;
                    return new Rect(
                        mi.rcWork.Left / dpi, mi.rcWork.Top / dpi,
                        (mi.rcWork.Right - mi.rcWork.Left) / dpi,
                        (mi.rcWork.Bottom - mi.rcWork.Top) / dpi);
                }
            }
            return SystemParameters.WorkArea;   // pre-HWND fallback: primary screen
        }

        // ── startup placement (main window) ──────────────────────────────

        /// <summary>
        /// Decides the main window's launch size/state from the current work
        /// area and any persisted state. Call from the constructor, BEFORE
        /// the window shows; XAML's CenterScreen still positions the
        /// first-launch default.
        /// </summary>
        public static void ApplyStartupPlacement(Window window)
        {
            Rect work = WorkAreaOf(window);
            _smallScreenStartup = work.Width < DesignWidth + FitMargin
                               || work.Height < DesignHeight + FitMargin;

            var (hasState, state, w, h, x, y) = ReadState();
            if (!hasState)
            {
                // first launch: design size on screens that fit it,
                // maximized on the 800×600 class — the XAML CenterScreen
                // positions both, and maximized ignores position entirely
                if (_smallScreenStartup)
                    window.WindowState = WindowState.Maximized;
                return;
            }

            // persisted launch: explicit bounds must beat CenterScreen
            window.WindowStartupLocation = WindowStartupLocation.Manual;

            if (state == WindowState.Maximized)
            {
                window.WindowState = WindowState.Maximized;   // fits by definition
                return;
            }

            // shrink-to-fit, then keep on-screen: covers the resolution jump
            // after GPU drivers install and undocked/rotated multi-monitor
            window.Width = Math.Clamp(w, MinWidth, Math.Max(MinWidth, work.Width));
            window.Height = Math.Clamp(h, MinHeight, Math.Max(MinHeight, work.Height));
            window.Left = Math.Clamp(x, work.Left, Math.Max(work.Left, work.Right - window.Width));
            window.Top = Math.Clamp(y, work.Top, Math.Max(work.Top, work.Bottom - window.Height));
        }

        /// <summary>
        /// Re-clamps a shown window whenever the work area changes (taskbar
        /// resized, display unplugged, resolution jumped) so it can never be
        /// left straddling a screen edge with its title bar off-screen.
        /// Unsubscribes itself when the window closes.
        /// </summary>
        public static void TrackWorkArea(Window window)
        {
            PropertyChangedEventHandler onStaticChanged = (s, e) =>
            {
                if (e.PropertyName == nameof(SystemParameters.WorkArea) && window.IsLoaded)
                    ClampIntoWorkArea(window);
            };
            SystemParameters.StaticPropertyChanged += onStaticChanged;
            window.Closed += (s, e) => SystemParameters.StaticPropertyChanged -= onStaticChanged;
        }

        /// <summary>Shrink and nudge a Normal-state window fully inside the work area.</summary>
        public static void ClampIntoWorkArea(Window window)
        {
            if (window.WindowState != WindowState.Normal) return;
            Rect work = WorkAreaOf(window);
            if (window.ActualWidth <= work.Width && window.ActualHeight <= work.Height
                && window.Left >= work.Left && window.Top >= work.Top
                && window.Left + window.ActualWidth <= work.Right
                && window.Top + window.ActualHeight <= work.Bottom) return;

            if (window.Width > work.Width) window.Width = work.Width;
            if (window.Height > work.Height) window.Height = work.Height;
            if (window.Left + window.ActualWidth > work.Right)
                window.Left = Math.Max(work.Left, work.Right - window.ActualWidth);
            if (window.Top + window.ActualHeight > work.Bottom)
                window.Top = Math.Max(work.Top, work.Bottom - window.ActualHeight);
            if (window.Left < work.Left) window.Left = work.Left;
            if (window.Top < work.Top) window.Top = work.Top;
        }

        // ── dialogs: never bigger than their monitor ─────────────────────

        /// <summary>
        /// Caps a dialog at 92% of its monitor's work area (parent stays
        /// visible behind) BEFORE layout runs, and lowers MinWidth/MinHeight
        /// floors that exceed the cap — a floor wider than the screen is a
        /// window that permanently clips. Call from the dialog constructor.
        /// </summary>
        public static void ConstrainToMonitor(Window dialog)
        {
            EventHandler onSourceInitialized = null;
            onSourceInitialized = (s, e) =>
            {
                dialog.SourceInitialized -= onSourceInitialized;
                Rect work = WorkAreaOf(dialog);
                double capW = Math.Max(360, work.Width * 0.92);
                double capH = Math.Max(240, work.Height * 0.92);
                dialog.MinWidth = Math.Min(dialog.MinWidth, capW);
                dialog.MinHeight = Math.Min(dialog.MinHeight, capH);
                dialog.MaxWidth = capW;
                dialog.MaxHeight = capH;
            };
            dialog.SourceInitialized += onSourceInitialized;
        }

        // ── state persistence ────────────────────────────────────────────
        // Five plain lines: state ("Normal"/"Maximized"), W, H, X, Y — all
        // invariant-culture. Maximized persists no bounds; WPF re-applies the
        // OS-restored bounds on un-maximize. A minimized close persists as
        // Normal with its RestoreBounds so a session never resumes hidden.

        /// <summary>Persist the window's final placement. Call from OnClosing while the state is still valid.</summary>
        public static void SaveState(Window window)
        {
            try
            {
                var state = window.WindowState;
                double w, h, x, y;
                string stateLine;
                if (state == WindowState.Maximized)
                {
                    stateLine = "Maximized";
                    w = h = x = y = 0;   // unused; the OS keeps restore bounds
                }
                else
                {
                    Rect bounds = state == WindowState.Minimized ? window.RestoreBounds
                        : new Rect(window.Left, window.Top, window.Width, window.Height);
                    if (bounds.IsEmpty || double.IsNaN(bounds.Width)) return;
                    stateLine = "Normal";
                    w = bounds.Width; h = bounds.Height; x = bounds.Left; y = bounds.Top;
                }
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(StatePath));
                System.IO.File.WriteAllText(StatePath, string.Join("\n",
                    stateLine,
                    w.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture),
                    h.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture),
                    x.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture),
                    y.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture)));
            }
            catch { /* read-only profile — placement lives for this session */ }
        }

        private static (bool ok, WindowState state, double w, double h, double x, double y) ReadState()
        {
            try
            {
                if (!System.IO.File.Exists(StatePath)) return default;
                var lines = System.IO.File.ReadAllLines(StatePath);
                if (lines.Length < 5) return default;

                double w = 0, h = 0, x = 0, y = 0;
                for (int i = 1; i < 5; i++)
                {
                    if (!double.TryParse(lines[i].Trim(), System.Globalization.NumberStyles.Float,
                            System.Globalization.CultureInfo.InvariantCulture, out var v))
                        return default;
                    switch (i)
                    {
                        case 1: w = v; break;
                        case 2: h = v; break;
                        case 3: x = v; break;
                        case 4: y = v; break;
                    }
                }
                if (w < MinWidth || h < MinHeight) return default;   // corrupt/stale floor
                return (true,
                    lines[0].Trim() == "Maximized" ? WindowState.Maximized : WindowState.Normal,
                    w, h, x, y);
            }
            catch { return default; }
        }
    }
}
