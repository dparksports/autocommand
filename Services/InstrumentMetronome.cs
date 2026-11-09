using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

#nullable enable

namespace AutoCommand.Services
{
    public enum InstrumentCost { Light = 0, Heavy = 1 }

    /// <summary>What a periodic instrument is and how it may be tuned.</summary>
    public sealed class InstrumentSpec
    {
        public string Id = "";
        public string Name = "";
        public string Description = "";
        public InstrumentCost Cost = InstrumentCost.Light;
        public int DefaultSeconds = 5;
        public int MinSeconds = 1;
        public int MaxSeconds = 60;
        public bool DefaultEnabled = true;
        /// <summary>The work; runs on a background thread unless
        /// RunOnUiThread marshals it through the dispatcher.</summary>
        public Func<Task> Callback = () => Task.CompletedTask;
        public bool RunOnUiThread;
    }

    /// <summary>Live state of one instrument — the unit the Settings page
    /// shows and calibrates.</summary>
    public sealed class InstrumentState
    {
        public InstrumentSpec Spec = new();
        public int Seconds;
        public bool Enabled;
        public bool UserSet;          // an explicit calibration disables auto-slow
        public DateTime LastRunUtc;
        public double LastMs;
        public DateTime NextRunUtc;
        public long Runs;
        public string Note = "";
        public bool Paused;           // runtime pause (e.g. hidden tab) — not persisted
        public bool Running;          // in-flight guard: a still-running callback is never re-dispatched
    }

    /// <summary>
    /// One scheduler for every periodic instrument, replacing scattered
    /// independent timers. Design properties:
    ///   • SPREAD — each instrument's first run is phase-offset by a stable
    ///     hash of its id, and heavy instruments never start within 1 s of
    ///     another heavy one, so equal-cadence work stops landing in the
    ///     same instant (the coincident WMI bursts behind the 1 Hz desktop
    ///     hitch).
    ///   • CALIBRATION — cadence and on/off per instrument, persisted to
    ///     %LOCALAPPDATA%\AutoCommand\cadence_settings.json and hot-applied.
    ///   • SELF-BUDGETING — a background (non-user-calibrated) instrument
    ///     whose run exceeds 500 ms auto-slows its cadence (×5, capped 30 s)
    ///     and says so in Note, instead of silently stuttering the machine.
    /// Callbacks must be self-contained; exceptions are caught and recorded
    /// as the instrument's Note.
    /// </summary>
    public sealed class InstrumentMetronome
    {
        public static readonly InstrumentMetronome Instance = new();
        private InstrumentMetronome() { }

        private readonly Dictionary<string, InstrumentState> _byId =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly object _gate = new();
        private CancellationTokenSource? _cts;
        private Task? _loop;
        private bool _running;
        private DateTime _lastHeavyStartUtc = DateTime.MinValue;

        private sealed class Persisted
        {
            public int seconds { get; set; }
            public bool enabled { get; set; } = true;
            public bool userSet { get; set; }
        }

        private static string StoreDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand");

        private static string StorePath => Path.Combine(StoreDir, "cadence_settings.json");

        /// <summary>The selectable cadences (seconds); 0 = Off.</summary>
        public static readonly int[] CadenceChoices = { 1, 3, 5, 6, 10, 15, 30, 60, 0 };

        public InstrumentState? Register(InstrumentSpec spec)
        {
            if (string.IsNullOrEmpty(spec.Id)) return null;
            lock (_gate)
            {
                if (_byId.TryGetValue(spec.Id, out var existing)) return existing;

                var s = new InstrumentState
                {
                    Spec = spec,
                    Seconds = Math.Clamp(spec.DefaultSeconds, spec.MinSeconds, spec.MaxSeconds),
                    Enabled = spec.DefaultEnabled,
                };
                // restore user calibration
                try
                {
                    var all = ReadStore();
                    if (all.TryGetValue(spec.Id, out var p))
                    {
                        if (p.seconds == 0 || (p.seconds >= spec.MinSeconds && p.seconds <= spec.MaxSeconds))
                            s.Seconds = p.seconds == 0 ? spec.MaxSeconds : p.seconds;
                        s.Enabled = p.enabled;
                        s.UserSet = p.userSet;
                    }
                }
                catch { /* fresh install */ }

                // phase spread: first run lands hash(id)-many seconds out
                // (≤5), never all instruments at t=0 together
                var now = DateTime.UtcNow;
                s.NextRunUtc = now.AddSeconds(PhaseSeconds(spec.Id, Math.Max(1, s.Seconds)));
                _byId[spec.Id] = s;
                return s;
            }
        }

        public void SetCadence(string id, int seconds, bool userSet)
        {
            lock (_gate)
            {
                if (!_byId.TryGetValue(id, out var s)) return;
                seconds = Math.Clamp(seconds, s.Spec.MinSeconds, s.Spec.MaxSeconds);
                s.Seconds = seconds;
                s.UserSet = userSet;
                if (userSet) s.Note = "";
                s.NextRunUtc = DateTime.UtcNow.AddSeconds(PhaseSeconds(id, seconds));
                SaveStore();
            }
        }

        public void SetEnabled(string id, bool enabled)
        {
            lock (_gate)
            {
                if (!_byId.TryGetValue(id, out var s)) return;
                if (s.Enabled == enabled) return;
                s.Enabled = enabled;
                if (enabled) s.NextRunUtc = DateTime.UtcNow.AddSeconds(1);
                SaveStore();
            }
        }

        /// <summary>Runtime pause without touching the persisted enabled
        /// state — hidden-tab gating, for instance.</summary>
        public void PauseInstrument(string id, bool paused)
        {
            lock (_gate)
            {
                if (_byId.TryGetValue(id, out var s))
                {
                    s.Paused = paused;
                    if (!paused) s.NextRunUtc = DateTime.UtcNow.AddSeconds(1);
                }
            }
        }

        public void ResetDefaults()
        {
            lock (_gate)
            {
                foreach (var s in _byId.Values)
                {
                    s.Seconds = Math.Clamp(s.Spec.DefaultSeconds, s.Spec.MinSeconds, s.Spec.MaxSeconds);
                    s.Enabled = s.Spec.DefaultEnabled;
                    s.UserSet = false;
                    s.Note = "";
                    s.NextRunUtc = DateTime.UtcNow.AddSeconds(PhaseSeconds(s.Spec.Id, Math.Max(1, s.Seconds)));
                }
                SaveStore();
            }
        }

        public int CadenceOf(string id)
        {
            lock (_gate) return _byId.TryGetValue(id, out var s) ? s.Seconds : 0;
        }

        public List<InstrumentState> Snapshot()
        {
            lock (_gate) return _byId.Values.OrderBy(s => s.Spec.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        public void Start()
        {
            lock (_gate)
            {
                if (_running) return;
                _running = true;
                _cts = new CancellationTokenSource();
                _loop = Task.Run(() => LoopAsync(_cts.Token));
            }
        }

        public void Stop()
        {
            lock (_gate)
            {
                if (!_running) return;
                _running = false;
                try { _cts?.Cancel(); } catch { }
                _cts = null;
            }
        }

        private async Task LoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                var due = new List<InstrumentState>();
                lock (_gate)
                {
                    var now = DateTime.UtcNow;
                    foreach (var s in _byId.Values)
                    {
                        if (!s.Enabled || s.Paused || now < s.NextRunUtc) continue;
                        if (s.Running)
                        {
                            // still in flight from a previous tick — the
                            // callback advances NextRunUtc only in its
                            // finally, so without this guard a slow (or
                            // hung) instrument would be re-dispatched every
                            // 500 ms and overlap itself indefinitely.
                            continue;
                        }
                        if (s.Spec.Cost == InstrumentCost.Heavy &&
                            (now - _lastHeavyStartUtc).TotalSeconds < 1)
                        {
                            // heavy instruments never coincide — push half a beat
                            s.NextRunUtc = now.AddSeconds(0.5);
                            continue;
                        }
                        due.Add(s);
                    }
                }
                foreach (var s in due)
                    _ = RunInstrumentAsync(s);
                try { await Task.Delay(500, ct); }
                catch (TaskCanceledException) { break; }
            }
        }

        private async Task RunInstrumentAsync(InstrumentState s)
        {
            var start = DateTime.UtcNow;
            lock (_gate)
            {
                if (s.Running) return; // lost a race with the dispatch loop's guard
                s.Running = true;
                if (s.Spec.Cost == InstrumentCost.Heavy)
                    _lastHeavyStartUtc = start;
            }

            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                if (s.Spec.RunOnUiThread && Application.Current?.Dispatcher is { } d)
                {
                    var inner = await d.InvokeAsync(() => s.Spec.Callback());
                    await inner;
                }
                else
                    await s.Spec.Callback();
            }
            catch (Exception ex)
            {
                lock (_gate) s.Note = $"last run failed: {ex.Message}";
            }
            finally
            {
                sw.Stop();
                lock (_gate)
                {
                    s.LastRunUtc = DateTime.UtcNow;
                    s.LastMs = sw.Elapsed.TotalMilliseconds;
                    s.Runs++;

                    // self-budgeting: a slow instrument that the user has not
                    // calibrated steps down instead of stuttering the machine
                    if (!s.UserSet && s.LastMs > 500 && s.Seconds < 30 && s.Runs % 5 == 0)
                    {
                        s.Seconds = Math.Min(s.Seconds * 5, 30);
                        s.Note = $"auto-slowed to {s.Seconds}s — last run took {(int)s.LastMs} ms on this machine";
                    }
                    else if (s.LastMs < 250 && s.Note.StartsWith("auto-slowed") && s.Runs % 5 == 0)
                    {
                        s.Note = "";
                    }

                    s.NextRunUtc = s.LastRunUtc.AddSeconds(Math.Max(1, s.Seconds));
                    s.Running = false;
                }
            }
        }

        private static int PhaseSeconds(string id, int seconds)
        {
            if (seconds <= 1) return 0;
            int h = 17;
            foreach (char c in id) h = h * 31 + c;
            int spread = Math.Min(seconds, 5);
            return Math.Abs(h) % spread;
        }

        private Dictionary<string, Persisted> ReadStore()
        {
            if (!File.Exists(StorePath)) return new Dictionary<string, Persisted>();
            var json = File.ReadAllText(StorePath);
            return JsonSerializer.Deserialize<Dictionary<string, Persisted>>(json)
                   ?? new Dictionary<string, Persisted>();
        }

        private void SaveStore()
        {
            try
            {
                Directory.CreateDirectory(StoreDir);
                var all = new Dictionary<string, Persisted>(StringComparer.OrdinalIgnoreCase);
                foreach (var s in _byId.Values)
                    all[s.Spec.Id] = new Persisted
                    {
                        seconds = s.Enabled ? s.Seconds : 0,
                        enabled = s.Enabled,
                        userSet = s.UserSet,
                    };
                File.WriteAllText(StorePath,
                    JsonSerializer.Serialize(all, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { /* calibration is best-effort persistence */ }
        }
    }
}
