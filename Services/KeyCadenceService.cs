using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

#nullable enable

namespace AutoCommand.Services
{
    /// <summary>
    /// Opt-in hourly keystroke-COUNT cadence for the Cadence tab — and the
    /// strictest privacy boundary in the app, by design:
    ///
    ///   • NOTHING is counted until the user flips the toggle (consent lives
    ///     in HKCU\Software\AutoCommand\KeyCadence, Consent = ask|yes|no;
    ///     "ask" behaves exactly like "no").
    ///   • The low-level keyboard hook does ONE thing: increment a counter
    ///     on key-down. The virtual key is read by the OS into the hook's
    ///     LPARAM and immediately discarded here — it is never stored,
    ///     logged, compared, or persisted. There is no code path from this
    ///     service to any per-key data structure, by construction.
    ///   • The only stored shape is {local day → 24 hourly counts}, kept for
    ///     8 days in %LOCALAPPDATA%\AutoCommand\key-cadence.json, never
    ///     synced anywhere.
    ///   • Disabling stops the hook immediately; the user is offered a
    ///     purge of the stored counts (and can keep them instead).
    ///   • Fail-open: if anything in the hook path throws, the hook is
    ///     removed — counting must never interfere with the user's typing.
    ///     The callback always forwards to CallNextHookEx and never eats a
    ///     keystroke.
    /// </summary>
    public sealed class KeyCadenceService
    {
        public static KeyCadenceService Instance { get; } = new();
        private KeyCadenceService() { }

        private const string RegKey = @"Software\AutoCommand\KeyCadence";
        private const int RetainedDays = 8;

        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;
        private const uint WM_QUIT = 0x0012;

        private readonly object _gate = new();
        private readonly Dictionary<string, int[]> _days =
            new(StringComparer.Ordinal);              // "yyyy-MM-dd" (local) → 24 hourly counts
        private long _pendingKeys;                    // hook thread → flusher
        private bool _loaded;
        private bool _enabled;
        private bool _instrumentRegistered;

        private IntPtr _hookHandle = IntPtr.Zero;
        private LowLevelKeyboardProc? _hookProc;      // kept referenced so the hook is never collected
        private Thread? _hookThread;
        private uint _hookThreadId;

        public bool IsEnabled => Volatile.Read(ref _enabled);

        // ── lifecycle ────────────────────────────────────────────────────

        /// <summary>Startup entry point (App.OnStartup). Reads consent; with
        /// consent=yes this installs the hook, otherwise it does nothing but
        /// register the flush instrument (whose callback no-ops while off).
        /// Also wires the exit flush — a last hour of counts must not die
        /// with the process.</summary>
        public void Initialize()
        {
            RegisterInstrument();
            if (ReadConsent() == "yes") EnableCore();

            var app = System.Windows.Application.Current;
            if (app != null)
            {
                app.Exit += (_, _) =>
                {
                    try { FlushPending(); StopHook(); } catch { }
                };
            }
        }

        /// <summary>Tab toggle ON. Idempotent.</summary>
        public void Enable()
        {
            WriteConsent("yes");
            EnableCore();
        }

        /// <summary>Tab toggle OFF. Stops counting immediately; the stored
        /// counts survive unless the caller passes purge=true (the tab asks).
        /// Idempotent.</summary>
        public void Disable(bool purgeFile)
        {
            WriteConsent("no");
            Volatile.Write(ref _enabled, false);
            FlushPending();           // credit what was counted while it was on
            StopHook();
            if (purgeFile)
            {
                lock (_gate)
                {
                    _days.Clear();
                    try { File.Delete(StorePath); } catch { }
                }
            }
        }

        private void EnableCore()
        {
            lock (_gate)
            {
                if (_enabled) return;
                LoadStoreLocked();
                _enabled = true;
            }
            StartHook();
        }

        // ── capture (hook on a dedicated message-pump thread) ────────────

        private void StartHook()
        {
            lock (_gate)
            {
                if (_hookThread != null) return;
                _hookProc = HookProc;
                _hookThread = new Thread(HookThreadRun)
                {
                    IsBackground = true,
                    Name = "key-cadence-hook",
                };
                _hookThread.SetApartmentState(ApartmentState.STA);
                _hookThreadId = (uint)_hookThread.ManagedThreadId;
                _hookThread.Start();
            }
        }

        private void HookThreadRun()
        {
            try
            {
                _hookHandle = SetWindowsHookEx(WH_KEYBOARD_LL, _hookProc!, GetModuleHandle(null), 0);
                if (_hookHandle == IntPtr.Zero)
                {
                    Volatile.Write(ref _enabled, false);   // fail-open: counting off, typing unaffected
                    return;
                }
                while (Volatile.Read(ref _enabled) && GetMessage(out _, IntPtr.Zero, 0, 0) > 0) { }
            }
            catch
            {
                Volatile.Write(ref _enabled, false);
            }
            finally
            {
                try { if (_hookHandle != IntPtr.Zero) UnhookWindowsHookEx(_hookHandle); } catch { }
                _hookHandle = IntPtr.Zero;
            }
        }

        private IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam)
        {
            try
            {
                // The LPARAM points at a KBDLLHOOKSTRUCT carrying the virtual
                // key — deliberately never read. A key-down is a count, full stop.
                if (nCode >= 0 &&
                    (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN))
                {
                    Interlocked.Increment(ref _pendingKeys);
                }
            }
            catch
            {
                // never let counting touch the user's input path
            }
            return CallNextHookEx(_hookHandle, nCode, wParam, lParam);
        }

        private void StopHook()
        {
            Thread? t;
            lock (_gate)
            {
                t = _hookThread;
                _hookThread = null;
            }
            if (t == null) return;
            try { PostThreadMessage(_hookThreadId, WM_QUIT, IntPtr.Zero, IntPtr.Zero); } catch { }
            try { t.Join(2000); } catch { }
            _hookThreadId = 0;
        }

        // ── flush + store ────────────────────────────────────────────────

        private void RegisterInstrument()
        {
            if (_instrumentRegistered) return;
            _instrumentRegistered = true;
            InstrumentMetronome.Instance.Register(new InstrumentSpec
            {
                Id = "key-cadence-flush",
                Name = "Key cadence flush (counts only)",
                Description = "Commits the opt-in hourly keystroke-COUNT cadence to key-cadence.json. " +
                              "Counts only — the hook never stores which keys were pressed, and the " +
                              "instrument no-ops entirely while the Cadence toggle is off.",
                Cost = InstrumentCost.Light,
                DefaultSeconds = 60,
                MinSeconds = 10,
                MaxSeconds = 600,
                Callback = () => { FlushPending(); return Task.CompletedTask; },
            });
        }

        /// <summary>Commits the pending counter into the current local-hour
        /// bucket and rewrites the store (atomic). Safe from any thread.</summary>
        public void FlushPending()
        {
            if (Volatile.Read(ref _enabled) != true && _pendingKeys == 0) return;
            long n = Interlocked.Exchange(ref _pendingKeys, 0);
            lock (_gate)
            {
                var now = DateTime.Now;
                var day = now.ToString("yyyy-MM-dd");
                if (!_days.TryGetValue(day, out var hours))
                {
                    hours = new int[24];
                    _days[day] = hours;
                }
                hours[now.Hour] += (int)Math.Min(n, int.MaxValue);
                PruneLocked();
                SaveStoreLocked();
            }
        }

        /// <summary>A copy of the tracked days ("yyyy-MM-dd" → int[24]).
        /// Days absent from the dictionary were never tracked — the UI must
        /// show them as "no data", never as zeros.</summary>
        public Dictionary<string, int[]> SnapshotDays()
        {
            lock (_gate)
            {
                FlushPending();
                var copy = new Dictionary<string, int[]>(StringComparer.Ordinal);
                foreach (var kv in _days)
                    copy[kv.Key] = (int[])kv.Value.Clone();
                return copy;
            }
        }

        private void PruneLocked()
        {
            var cutoff = DateTime.Now.AddDays(-RetainedDays).ToString("yyyy-MM-dd");
            var stale = new List<string>();
            foreach (var key in _days.Keys)
                if (string.CompareOrdinal(key, cutoff) < 0) stale.Add(key);
            foreach (var key in stale) _days.Remove(key);
        }

        private void LoadStoreLocked()
        {
            if (_loaded) return;
            _loaded = true;
            try
            {
                if (!File.Exists(StorePath)) return;
                var doc = JsonSerializer.Deserialize<StoreFile>(File.ReadAllText(StorePath));
                if (doc?.Days == null) return;
                foreach (var kv in doc.Days)
                    if (kv.Value != null && kv.Value.Length == 24)
                        _days[kv.Key] = kv.Value;
            }
            catch { /* unreadable store — start fresh, same as ConfirmPrefs */ }
        }

        private void SaveStoreLocked()
        {
            try
            {
                Directory.CreateDirectory(StoreDir);
                var tmp = StorePath + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(
                    new StoreFile { V = 1, Days = _days },
                    new JsonSerializerOptions { WriteIndented = false }));
                File.Move(tmp, StorePath, overwrite: true);
            }
            catch { /* best-effort — the live buckets survive in memory */ }
        }

        private string StoreDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand");

        private string StorePath => Path.Combine(StoreDir, "key-cadence.json");

        private sealed class StoreFile
        {
            public int V { get; set; }
            public Dictionary<string, int[]>? Days { get; set; }
        }

        // ── consent (HKCU, same store style as UsagePingService) ─────────

        public string ReadConsent()
        {
            try
            {
                using var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegKey);
                return (string)k?.GetValue("Consent") ?? "ask";
            }
            catch { return "ask"; }
        }

        private void WriteConsent(string value)
        {
            try
            {
                using var root = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                    @"Software\AutoCommand", writable: true);
                using var k = root?.CreateSubKey("KeyCadence", writable: true);
                k?.SetValue("Consent", value);
            }
            catch { /* consent write failed — the in-memory state still governs */ }
        }

        // ── Win32 (the whole surface is four functions + a message) ──────

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandle(string? lpModuleName);

        [DllImport("user32.dll")]
        private static extern int GetMessage(out NativeMessage lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool PostThreadMessage(uint threadId, uint msg, IntPtr wParam, IntPtr lParam);

        private struct NativeMessage
        {
            public IntPtr Hwnd;
            public uint Message;
            public IntPtr WParam;
            public IntPtr LParam;
            public uint Time;
            public IntPtr PtX;
            public IntPtr PtY;
        }
    }
}
