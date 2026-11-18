using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace AutoCommand.Contain.Core
{
    /// <summary>
    /// Who the block-page proxy actually contains. The WinINET system proxy
    /// is machine-wide — Windows has no per-app proxy setting for desktop
    /// apps — so "proxy only the browsers" cannot be expressed in the
    /// proxy setting itself. It is expressed here instead: every accepted
    /// connection is attributed to its client process through the kernel
    /// TCP table (the same iphlpapi trick SinkholeService uses for its
    /// peer, run while the client socket is still open), and only in-scope
    /// images reach the block decision at all. Everyone else gets a pure
    /// byte-for-byte forward — no block inventory, no DNS, no decryption,
    /// no block page — which is as close to "goes direct" as the
    /// system-proxy route allows, and stays fully covered by the kernel
    /// firewall layer (process and IP blocks never touch this service).
    ///
    /// Defaults are browsers-only with WebView2 OUT: msedgewebview2.exe is
    /// an embedded component hosted by arbitrary desktop apps (Teams,
    /// Widgets, Outlook, …), not a browser the user opened, and those host
    /// processes are not necessarily trustworthy — so embedded web content
    /// is not treated as browser traffic unless the user says so.
    ///
    /// Settings are read live per connection, so a toggle applies to the
    /// next request without restarting the listener:
    ///
    ///   HKCU\Software\AutoCommand\ProxyScope
    ///     Mode            "browsers" (default) | "all"
    ///     IncludeWebView2 "0" (default) | "1"
    ///
    /// An optional %LOCALAPPDATA%\AutoCommand\browsers.txt replaces the
    /// embedded list (one image name per line, # comments) for browsers
    /// that ship under another name; the WebView2 flag stays authoritative
    /// over msedgewebview2.exe either way, in both directions.
    /// </summary>
    public static class ProxyScope
    {
        public const string ModeBrowsersOnly = "browsers";
        public const string ModeAllApps = "all";
        public const string WebView2Image = "msedgewebview2.exe";

        private const string RegKey = @"Software\AutoCommand\ProxyScope";
        private const string ListFileName = "browsers.txt";

        /// <summary>The embedded scope list (image names, matched without
        /// path or case). Plain text files and regedit both work on it —
        /// same readable-policy stance as every other app setting.</summary>
        private static readonly string[] DefaultBrowsers =
            { "msedge.exe", "chrome.exe", "brave.exe", "firefox.exe", "opera.exe", "vivaldi.exe" };

        // ── test seams (house pattern: BlockImpactProbe.Resolver) ─────────

        /// <summary>Pin the mode outright (null = registry + default).</summary>
        internal static string ModeOverride;

        /// <summary>Pin the WebView2 flag outright (null = registry + default).</summary>
        internal static bool? IncludeWebView2Override;

        /// <summary>Pin the scope list outright (null = browsers.txt + defaults).</summary>
        internal static string[] BrowserListOverride;

        /// <summary>Client ephemeral port → image path (or null). Null seam =
        /// the real kernel-table lookup; the self-test pins images per port
        /// because its own process is not a browser.</summary>
        internal static Func<int, string> ClientImageResolver;

        /// <summary>Redirect the browsers.txt path (tests never touch the
        /// real profile directory).</summary>
        internal static string ListFileOverride;

        // ── settings ──────────────────────────────────────────────────────

        public static string Mode
        {
            get
            {
                if (ModeOverride != null) return ModeOverride;
                try
                {
                    using var k = Registry.CurrentUser.OpenSubKey(RegKey);
                    var v = k?.GetValue("Mode") as string;
                    if (v == ModeBrowsersOnly || v == ModeAllApps) return v;
                }
                catch { }
                return ModeBrowsersOnly;
            }
        }

        public static bool IncludeWebView2
        {
            get
            {
                if (IncludeWebView2Override.HasValue) return IncludeWebView2Override.Value;
                try
                {
                    using var k = Registry.CurrentUser.OpenSubKey(RegKey);
                    return (k?.GetValue("IncludeWebView2") as string) == "1";
                }
                catch { return false; }
            }
        }

        /// <summary>The scope as the UI states it.</summary>
        public static string ModeText => Mode == ModeAllApps
            ? "all apps"
            : IncludeWebView2 ? "browsers only (+WebView2)" : "browsers only";

        public static void SetMode(string mode)
        {
            if (mode != ModeBrowsersOnly && mode != ModeAllApps) return;
            try { using var k = OpenKey(); k?.SetValue("Mode", mode); } catch { }
        }

        public static void SetIncludeWebView2(bool on)
        {
            try { using var k = OpenKey(); k?.SetValue("IncludeWebView2", on ? "1" : "0"); } catch { }
        }

        private static RegistryKey OpenKey(bool writable = true)
        {
            using var root = Registry.CurrentUser.OpenSubKey(@"Software\AutoCommand", writable);
            return root?.CreateSubKey("ProxyScope", writable: writable);
        }

        // ── the per-connection verdict ────────────────────────────────────

        /// <summary>"all apps" contains everyone; browsers-only contains the
        /// scope list. An UNKNOWN client tunnels (fail-open): a missed
        /// attribution must degrade to "go direct", never to "the internet
        /// stopped" — kernel firewall blocks still cover that process.</summary>
        public static bool ShouldContain(string imagePath)
        {
            if (Mode != ModeBrowsersOnly) return true;
            if (string.IsNullOrWhiteSpace(imagePath)) return false;
            string name = Path.GetFileName(imagePath.Trim());
            foreach (var entry in EffectiveBrowsers())
                if (name.Equals(entry.Trim(), StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        /// <summary>The effective scope list: browsers.txt (when present)
        /// replaces the embedded defaults; the WebView2 flag stays
        /// authoritative over msedgewebview2.exe either way, in both
        /// directions. Cached on the file's mtime so per-connection calls
        /// do not re-read the file; settings are always read live.</summary>
        public static IReadOnlyList<string> EffectiveBrowsers()
        {
            IEnumerable<string> list;
            if (BrowserListOverride != null) list = BrowserListOverride;
            else if (ReadListFile() is { } file) list = file;
            else list = DefaultBrowsers;

            list = IncludeWebView2
                ? list.Append(WebView2Image)
                : list.Where(n => !n.Equals(WebView2Image, StringComparison.OrdinalIgnoreCase));
            return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        private static (DateTime Mtime, string[] Lines) _listCache;

        private static string[] ReadListFile()
        {
            string path = ListFileOverride ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "AutoCommand", ListFileName);
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists) return null;
                var mtime = info.LastWriteTimeUtc;
                if (_listCache.Mtime == mtime && _listCache.Lines != null) return _listCache.Lines;
                var lines = File.ReadAllLines(path)
                    .Select(l => { int c = l.IndexOf('#'); return (c >= 0 ? l[..c] : l).Trim(); })
                    .Where(l => l.Length > 0).ToArray();
                _listCache = (mtime, lines);
                return lines.Length > 0 ? lines : null;   // empty file = defaults
            }
            catch { return null; }   // unreadable file = defaults, never a scope failure
        }

        // ── client attribution (iphlpapi, same shape as SinkholeService) ──

        /// <summary>Image path for one accepted connection: the client's
        /// ephemeral port pairs with a kernel-table row whose remote side is
        /// our listener. MUST be called while the client socket is still
        /// open — the row dies with it. Null when anything misses (client
        /// already closed, process exited, table raced): the caller treats
        /// null as "tunnel", never as "block".</summary>
        public static string ImageForClientPort(int clientPort, int listenerPort)
        {
            if (ClientImageResolver != null)
            {
                try { return ClientImageResolver(clientPort); }
                catch { return null; }
            }
            int pid = FindClientPid(clientPort, listenerPort);
            if (pid <= 0) return null;
            try { return Process.GetProcessById(pid)?.MainModule?.FileName; }
            catch { return null; }   // gone or inaccessible — tunnel
        }

        private const int AfInet = 2;
        private const int TcpTableOwnerPidAll = 5;
        private static readonly uint LoopbackBytes = BitConverter.ToUInt32(new byte[] { 127, 0, 0, 1 }, 0);

        [DllImport("iphlpapi.dll")]
        private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int size, bool order, int af, int tableClass, int reserved);

        private static int FindClientPid(int clientPort, int listenerPort)
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
            if (size <= 0) return 0;

            var table = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(table, ref size, false, AfInet, TcpTableOwnerPidAll, 0) != 0)
                    return 0;

                int rows = Marshal.ReadInt32(table);
                long rowPtr = table + 4;   // DWORD dwNumEntries, then MIB_TCPROW_OWNER_PID rows:
                                           // state(4) localAddr(4) localPort(4) remoteAddr(4) remotePort(4) pid(4)
                for (int i = 0; i < rows; i++, rowPtr += 24)
                {
                    uint localAddr = (uint)Marshal.ReadInt32((IntPtr)(rowPtr + 4));
                    uint localPort = (uint)Marshal.ReadInt32((IntPtr)(rowPtr + 8)) & 0xFFFF;
                    uint remoteAddr = (uint)Marshal.ReadInt32((IntPtr)(rowPtr + 12));
                    uint remotePort = (uint)Marshal.ReadInt32((IntPtr)(rowPtr + 16)) & 0xFFFF;
                    uint pid = (uint)Marshal.ReadInt32((IntPtr)(rowPtr + 20));

                    // the client's row: local = its ephemeral port, remote = our listener
                    if (Swap16((ushort)localPort) == clientPort
                        && remoteAddr == LoopbackBytes && Swap16((ushort)remotePort) == listenerPort
                        && localAddr == LoopbackBytes)
                        return (int)pid;
                }
                return 0;
            }
            finally { Marshal.FreeHGlobal(table); }
        }

        private static ushort Swap16(ushort v) => (ushort)((v >> 8) | (v << 8));
    }
}
