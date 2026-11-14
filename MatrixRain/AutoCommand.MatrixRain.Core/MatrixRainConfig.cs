using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AutoCommand.Matrix
{
    /// <summary>
    /// User settings for the rain — plain, inspectable JSON beside the exe
    /// (matrix_rain.json), same convention as the main app's tx_threshold.txt
    /// / ignored_processes.txt. Edited by hand, hot-reloaded on save: colors,
    /// font, dock side, widths and rates all apply without a restart.
    /// </summary>
    public class MatrixRainConfig
    {
        /// <summary>left | right | full | manual — where the overlay lives.</summary>
        public string Dock { get; set; } = "right";

        /// <summary>cinema | instrument — cinema (the default) is the
        /// movie's look: a dense wall of green rain on every column,
        /// continuous varied-speed streams, white lead glyphs, mutating
        /// trail characters, pure black behind; real transmits still ride
        /// on top brighter, bloomed and PID-labeled. instrument is the
        /// event-driven stillness: nothing moves without a packet.</summary>
        public string Style { get; set; } = "cinema";

        /// <summary>desktop | overlay — "desktop" parents the pane to the
        /// wallpaper host (WorkerW): the rain paints over the desktop but
        /// APPLICATION WINDOWS COVER IT, visible only where the desktop
        /// shows. "overlay" floats above everything (the original
        /// behavior).</summary>
        public string Surface { get; set; } = "desktop";

        /// <summary>Overlay width in DIPs for left/right docking.</summary>
        public int WidthPx { get; set; } = 280;

        /// <summary>Window-level opacity (0.30–1.00). 1.0 = fully solid rain.</summary>
        public double Opacity { get; set; } = 0.92;

        /// <summary>When true the overlay ignores the mouse entirely.</summary>
        public bool ClickThrough { get; set; } = false;

        /// <summary>Any installed font family, e.g. "Consolas", "Cascadia Mono".</summary>
        public string FontFamily { get; set; } = "Consolas";

        /// <summary>
        /// Optional absolute path to a .ttf/.otf — when set it wins over
        /// FontFamily, so the rain can run in the user's own font file.
        /// </summary>
        public string FontFile { get; set; } = "";

        /// <summary>Glyph cell font size in DIPs.</summary>
        public int FontSizePx { get; set; } = 18;

        /// <summary>katakana (default — katakana + machine symbols, no
        /// roman letters or digits: a field foreign to humankind) |
        /// katakana-latin | latin | digits, or a literal string of
        /// characters to rain.</summary>
        public string Charset { get; set; } = "katakana";

        public RainColors Colors { get; set; } = new RainColors();

        /// <summary>Letters emitted per TX packet; auto-scaled down under
        /// heavy traffic so a busy PID streams instead of solidifying.</summary>
        public double LettersPerTransmit { get; set; } = 1.0;

        /// <summary>Cap on rain columns; the stalest PIDs drop out first.</summary>
        public int MaxColumns { get; set; } = 9;

        /// <summary>Firewall block-inventory poll (the red-mode source of
        /// truth) in seconds — same cadence as the main app's monitor.</summary>
        public int BlockPollSeconds { get; set; } = 60;

        /// <summary>Draw the PID + process name label atop each column.</summary>
        public bool ShowLabels { get; set; } = true;

        /// <summary>Optional: also rain (in Colors.Rx) on received packets.
        /// Default off — the rain reads as outbound transmits only.</summary>
        public bool RxMode { get; set; } = false;

        /// <summary>Dim backdrop field of glyphs behind the rain — a steady
        /// brightness (its layer is never touched by the trail fade),
        /// drifting down much slower than the falling streams.</summary>
        public bool Ambient { get; set; } = true;

        /// <summary>Seconds per row of backdrop drift; 0 (the default)
        /// FREEZES the backdrop — the background characters never change
        /// on their own, and only falling wakes etch into them. That
        /// stillness is the magic; drift is an opt-in flavor.</summary>
        public double AmbientDriftSeconds { get; set; } = 0;

        /// <summary>Fraction of backdrop cells carrying a glyph (0.1–1.0);
        /// below 1.0 leaves breathing holes in the field.</summary>
        public double AmbientDensity { get; set; } = 0.9;

        /// <summary>Pseudo-3D pop for the falling LEAD glyph — deliberately
        /// SUBTLE by default (1.06): at a glance the lead reads the same
        /// height as the background characters; watching carefully reveals
        /// the slight scale, the faint shadow and the soft bloom. 1.0 =
        /// flat, no shadow; up to 1.6 for a dramatic pop.</summary>
        public double ZLift { get; set; } = 1.06;

        /// <summary>Glow halo around the falling LEAD glyph — the single
        /// bloomed element; wake characters never bloom.</summary>
        public bool Bloom { get; set; } = true;

        /// <summary>Trail length in CHARACTERS behind the lead (clamped
        /// 8–80): wakeFadeSeconds x fallRowsPerSecond. The trailing
        /// characters share the lead's brightness family, each one log-step
        /// dimmer by distance — never by time, so idle streams freeze
        /// mid-fall instead of dissolving.</summary>
        public double WakeFadeSeconds { get; set; } = 2.0;

        /// <summary>Fall-speed ceiling in glyph rows per second (5–200),
        /// also adjustable live from the tray (Fall slower / faster).
        /// Default 25 — the original 50 halved, per the house request.</summary>
        public double FallRowsPerSecond { get; set; } = 25;

        /// <summary>Streams complete their fall when traffic goes quiet: no
        /// packet movement for two seconds stops NEW drops from spawning
        /// (the banked budget stays banked), while everything already
        /// falling — data streams and the cinema deco wall — finishes its
        /// descent at full fall speed; once nothing is falling the frame
        /// loop idles (an empty quiet pane costs a snapshot check per tick,
        /// not a redraw) until the next packet, which re-arms the wall and
        /// un-banks the letters. Off = the classic always-falling
        /// wall.</summary>
        public bool IdleStill { get; set; } = true;

        public class RainColors
        {
            /// <summary>Lead glyph of a falling stream — near-white green.</summary>
            public string Head { get; set; } = "#E8FFE8";
            /// <summary>The classic Matrix green trail.</summary>
            public string Trail { get; set; } = "#00FF41";
            /// <summary>A traffic-blocked PID rains this instead.</summary>
            public string Blocked { get; set; } = "#FF3333";
            /// <summary>Lead glyph while blocked.</summary>
            public string BlockedHead { get; set; } = "#FFDDDD";
            /// <summary>PID / process-name labels atop the columns.</summary>
            public string Label { get; set; } = "#7FFF9F";
            /// <summary>Rx glyph tint when RxMode is on.</summary>
            public string Rx { get; set; } = "#2E7DFF";
            /// <summary>The steady backdrop field behind the rain.</summary>
            public string Ambient { get; set; } = "#0E5C1F";
        }

        // ------------------------------------------------------------------
        // Load / save / hot reload
        // ------------------------------------------------------------------

        public static string ConfigPath =>
            Path.Combine(AppContext.BaseDirectory, "matrix_rain.json");

        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = true,
            // Hand edits shouldn't silently no-op over key case — and a
            // duplicated-in-different-case key must not wedge the load.
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() },
            DefaultIgnoreCondition = JsonIgnoreCondition.Never
        };

        /// <summary>Persists the config (normalized). The tray writes
        /// through here; the ConfigWatcher then hot-applies the change like
        /// a hand edit would.</summary>
        public static void Save(MatrixRainConfig cfg)
        {
            cfg.Normalize();
            try { File.WriteAllText(ConfigPath, JsonSerializer.Serialize(cfg, JsonOpts)); }
            catch { /* read-only folder — settings live for this session */ }
        }

        /// <summary>Loads the config, writing a commented default file on
        /// first run so the knobs are discoverable where the exe lives.</summary>
        public static MatrixRainConfig LoadOrDefault()
        {
            try
            {
                if (File.Exists(ConfigPath))
                {
                    var cfg = JsonSerializer.Deserialize<MatrixRainConfig>(File.ReadAllText(ConfigPath), JsonOpts);
                    if (cfg != null) { cfg.Normalize(); return cfg; }
                }
            }
            catch { /* a hand-edited typo must not stop the rain — fall back to defaults */ }

            var fresh = new MatrixRainConfig();
            try
            {
                // "//" keys carry inline documentation; the loader ignores them.
                var doc = new Dictionary<string, object>
                {
                    ["// dock"] = "left | right | full (whole screen, explicit) | manual (position below)",
                    ["// style"] = "cinema = the movie look (dense green rain everywhere, data streams on top) | instrument = event-driven stillness",
                    ["// surface"] = "desktop = behind app windows, over the wallpaper (default) | overlay = above everything",
                    ["// fontFile"] = "optional absolute path to a .ttf/.otf — overrides fontFamily",
                    ["// charset"] = "katakana (default - no roman letters or digits, a field foreign to humankind) | katakana-latin | latin | digits - or a literal set of characters",
                    ["// lettersPerTransmit"] = "falling letters per TX packet (auto-scales down under load)",
                    ["// maxColumns"] = "the pane carries exactly one column per alive process, hard-capped below ten",
                    ["// colors"] = "any #RRGGBB — head/trail/blocked/blockedHead/label/rx/ambient",
                    ["// ambient"] = "dim backdrop field behind the rain, frozen by default (ambientDriftSeconds 0 = the background never changes on its own; only falling wakes etch into it)",
                    ["// zLift"] = "subtle lead-glyph elevation (1.06 default - reads same-height as the background unless you watch carefully; 1.0 = flat, up to 1.6 = dramatic)",
                    ["// bloom"] = "glow halo on the falling lead glyph only (the wake never blooms)",
                    ["// wakeFadeSeconds"] = "wake character lifetime behind the lead, fading on a logarithmic curve",
                    ["// fallRowsPerSecond"] = "fall-speed ceiling in glyph rows per second (default 25 = the original 50 halved)"
                };
                var merged = new Dictionary<string, object>();
                foreach (var kv in doc) merged[kv.Key] = kv.Value;
                foreach (var prop in typeof(MatrixRainConfig).GetProperties())
                {
                    if (!prop.CanRead || prop.Name == nameof(ConfigPath)) continue;
                    object v = prop.GetValue(fresh);
                    if (prop.PropertyType == typeof(RainColors) && v is RainColors rc)
                    {
                        var colors = new Dictionary<string, object>();
                        foreach (var cp in typeof(RainColors).GetProperties())
                            colors[cp.Name] = cp.GetValue(rc);
                        merged[prop.Name] = colors;
                    }
                    else merged[prop.Name] = v;
                }
                File.WriteAllText(ConfigPath,
                    JsonSerializer.Serialize(merged, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { /* unwritable folder — run on in-memory defaults */ }
            return fresh;
        }

        /// <summary>Clamps hand-edited values into safe ranges.</summary>
        public void Normalize()
        {
            Dock = Dock?.Trim().ToLowerInvariant() is "left" or "full" or "manual" ? Dock.Trim().ToLowerInvariant() : "right";
            Style = Style?.Trim().ToLowerInvariant() == "instrument" ? "instrument" : "cinema";
            Surface = Surface?.Trim().ToLowerInvariant() == "overlay" ? "overlay" : "desktop";
            WidthPx = Math.Clamp(WidthPx, 120, 4096);
            Opacity = Math.Clamp(Opacity, 0.30, 1.0);
            FontSizePx = Math.Clamp(FontSizePx, 9, 48);
            LettersPerTransmit = Math.Clamp(LettersPerTransmit, 0.05, 20.0);
            // one column per alive process, never ten or more
            MaxColumns = Math.Clamp(MaxColumns, 1, 9);
            BlockPollSeconds = Math.Clamp(BlockPollSeconds, 10, 3600);
            AmbientDriftSeconds = Math.Clamp(AmbientDriftSeconds, 0.0, 60.0);
            AmbientDensity = Math.Clamp(AmbientDensity, 0.1, 1.0);
            ZLift = Math.Clamp(ZLift, 1.0, 1.6);
            WakeFadeSeconds = Math.Clamp(WakeFadeSeconds, 0.3, 10.0);
            FallRowsPerSecond = Math.Clamp(FallRowsPerSecond, 5.0, 200.0);
            if (string.IsNullOrWhiteSpace(FontFamily)) FontFamily = "Consolas";
            if (string.IsNullOrWhiteSpace(Charset)) Charset = "katakana";
            Colors ??= new RainColors();
        }

        /// <summary>True when any of the color/font/charset knobs changed
        /// relative to <paramref name="other"/> (atlas rebuild needed).</summary>
        public bool VisualsDifferFrom(MatrixRainConfig other)
        {
            return other == null
                || !string.Equals(FontFamily, other.FontFamily, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(FontFile, other.FontFile, StringComparison.OrdinalIgnoreCase)
                || FontSizePx != other.FontSizePx
                || !string.Equals(Charset, other.Charset, StringComparison.Ordinal)
                || ShowLabels != other.ShowLabels
                || Ambient != other.Ambient
                || Math.Abs(AmbientDensity - other.AmbientDensity) > 0.001
                || Math.Abs(ZLift - other.ZLift) > 0.001
                || Bloom != other.Bloom
                || Colors.Head != other.Colors.Head
                || Colors.Trail != other.Colors.Trail
                || Colors.Blocked != other.Colors.Blocked
                || Colors.BlockedHead != other.Colors.BlockedHead
                || Colors.Label != other.Colors.Label
                || Colors.Rx != other.Colors.Rx
                || Colors.Ambient != other.Colors.Ambient;
        }
    }

    /// <summary>Watches matrix_rain.json and debounces a Changed event onto
    /// the UI thread — edit the file, the rain re-skins within ~300 ms.</summary>
    public sealed class ConfigWatcher : IDisposable
    {
        public event Action<MatrixRainConfig> Changed;

        private readonly FileSystemWatcher _watcher;
        private readonly System.Windows.Threading.Dispatcher _dispatcher;
        private DateTime _lastFireUtc = DateTime.MinValue;
        private readonly object _debounceLock = new();

        public ConfigWatcher()
        {
            _dispatcher = System.Windows.Threading.Dispatcher.FromThread(System.Threading.Thread.CurrentThread);
            _watcher = new FileSystemWatcher(
                Path.GetDirectoryName(MatrixRainConfig.ConfigPath),
                Path.GetFileName(MatrixRainConfig.ConfigPath))
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                EnableRaisingEvents = true
            };
            _watcher.Changed += (s, e) => OnFileTouched();
            _watcher.Created += (s, e) => OnFileTouched();
        }

        private void OnFileTouched()
        {
            // Editors save in bursts (write, flush, meta) — collapse them.
            lock (_debounceLock)
            {
                if ((DateTime.UtcNow - _lastFireUtc).TotalMilliseconds < 300) return;
                _lastFireUtc = DateTime.UtcNow;
            }
            var cfg = MatrixRainConfig.LoadOrDefault();
            void raise() => Changed?.Invoke(cfg);
            if (_dispatcher != null) _dispatcher.BeginInvoke(raise);
            else raise();
        }

        public void Dispose() => _watcher.Dispose();
    }
}
