using System;
using System.Drawing;
using System.Windows.Forms;

namespace AutoCommand.Light
{
    /// <summary>
    /// The persistent surface — the HIG "menu bar item" in Windows
    /// clothing. Three states, readable without color (the tooltip and
    /// menu carry the words): quiet green, amber while an app waits for
    /// an answer, red the day attempts were stopped. Click opens the app
    /// on Today; the menu carries the guarded actions (review asks,
    /// temporarily open everything).
    /// </summary>
    public sealed class TrayController : IDisposable
    {
        private readonly NotifyIcon _icon;
        private readonly Func<(string Tooltip, TrayState State)> _readState;
        private readonly Action _openToday;
        private readonly Action _openApps;
        private readonly Action _openTemporarily;
        private readonly Action _quit;

        public enum TrayState { Quiet, Asking, Stopped }

        public TrayController(
            Func<(string, TrayState)> readState,
            Action openToday, Action openApps, Action openTemporarily, Action quit)
        {
            _readState = readState;
            _openToday = openToday;
            _openApps = openApps;
            _openTemporarily = openTemporarily;
            _quit = quit;

            _icon = new NotifyIcon
            {
                Icon = Render(StateColor(TrayState.Quiet)),
                Text = "AutoCommand Light — quiet",
                Visible = true,
            };
            _icon.DoubleClick += (s, e) => _openToday();

            var menu = new ContextMenuStrip();
            menu.Items.Add("Open AutoCommand Light", null, (s, e) => _openToday());
            menu.Items.Add("Review apps waiting", null, (s, e) => _openApps());
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Open the internet for everyone — 10 minutes", null,
                (s, e) => _openTemporarily());
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Quit", null, (s, e) => _quit());
            _icon.ContextMenuStrip = menu;
        }

        /// <summary>Re-render only when the state actually changes — a
        /// tray icon redraw per attempt would be waste, not feedback.</summary>
        private TrayState _lastState = (TrayState)(-1);
        private string _lastTooltip = "";

        /// <summary>The gate's numbers, spoken in tray grammar.</summary>
        public void UpdateFrom(int asks, int attempts)
        {
            var state = asks > 0 ? TrayState.Asking
                : attempts > 0 ? TrayState.Stopped
                : TrayState.Quiet;
            var tooltip = state switch
            {
                TrayState.Asking => $"{asks} app(s) waiting for your answer",
                TrayState.Stopped => $"{attempts} attempt(s) stopped today",
                _ => "AutoCommand Light — quiet",
            };
            Update(tooltip, state);
        }

        public void Update(string tooltip, TrayState state)
        {
            if (state == _lastState && tooltip == _lastTooltip) return;
            _lastState = state;
            _lastTooltip = tooltip;
            _icon.Text = tooltip;
            var old = _icon.Icon;
            _icon.Icon = Render(StateColor(state));
            old.Dispose();
        }

        private static Color StateColor(TrayState state) => state switch
        {
            TrayState.Asking => Color.FromArgb(0xC7, 0x77, 0x00),
            TrayState.Stopped => Color.FromArgb(0xC4, 0x3D, 0x36),
            _ => Color.FromArgb(0x1E, 0x9E, 0x4F),
        };

        /// <summary>A lock, drawn: body rectangle + shackle arc, white on
        /// the state color. Drawn at runtime so the icon always matches
        /// the state without shipping icon assets.</summary>
        private static Icon Render(Color color)
        {
            using var bmp = new Bitmap(32, 32);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                using var back = new SolidBrush(color);
                g.FillEllipse(back, 1, 1, 30, 30);
                using var white = new Pen(Color.White, 2.6f);
                // shackle
                g.DrawArc(white, 10, 7, 12, 12, 180, 180);
                // body
                using var body = new SolidBrush(Color.White);
                g.FillRectangle(body, 8, 13, 16, 12);
            }
            return Icon.FromHandle(bmp.GetHicon());
        }

        public void Dispose()
        {
            _icon.Visible = false;
            _icon.Dispose();
        }
    }
}
