using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AutoCommand.Light
{
    /// <summary>
    /// The window facts behind the interactive-use courtesy: which image
    /// is foreground, and which images own visible top-level windows.
    /// Measured on demand (a hold is rare), cached for a few seconds so a
    /// burst of attempts costs one probe. Pure Win32 — no WMI walks.
    /// </summary>
    internal static class WindowProbe
    {
        private static (DateTime At, string Foreground, HashSet<string> Visible) _cache =
            (DateTime.MinValue, "", new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        private static readonly object Lock = new();
        private static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(5);

        public static string ForegroundImageBase()
        {
            Probe();
            return _cache.Foreground;
        }

        public static HashSet<string> VisibleImageBases()
        {
            Probe();
            return _cache.Visible;
        }

        /// <summary>The gate's courtesy question, answered with the cached
        /// window facts plus the launch-parent fact the rows already carry.</summary>
        public static bool IsUserDriven(string key, string? parentImage)
        {
            Probe();
            return Core.InteractiveUse.IsUserDriven(key, _cache.Foreground, _cache.Visible, parentImage);
        }

        private static void Probe()
        {
            lock (Lock)
            {
                if (DateTime.UtcNow - _cache.At < CacheFor) return;
                var fg = "";
                var visible = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                try
                {
                    var fgHwnd = GetForegroundWindow();
                    if (fgHwnd != IntPtr.Zero)
                        fg = ProcessNameOfWindow(fgHwnd);

                    EnumWindows((hWnd, lParam) =>
                    {
                        if (!IsWindowVisible(hWnd)) return true;
                        if (GetWindowTextLength(hWnd) == 0) return true;
                        var name = ProcessNameOfWindow(hWnd);
                        if (name.Length > 0) visible.Add(name);
                        return true;
                    }, IntPtr.Zero);
                }
                catch { // a failed probe is a failed courtesy, not a crash
                }

                _cache = (DateTime.UtcNow, fg, visible);
            }
        }

        private static string ProcessNameOfWindow(IntPtr hWnd)
        {
            try
            {
                if (GetWindowThreadProcessId(hWnd, out var pid) == 0 || pid == 0) return "";
                using var p = Process.GetProcessById((int)pid);
                var name = p.ProcessName;
                return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? name[..^4] : name;
            }
            catch { return ""; }   // the process died between enumerate and query
        }

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowTextLength(IntPtr hWnd);
    }
}
