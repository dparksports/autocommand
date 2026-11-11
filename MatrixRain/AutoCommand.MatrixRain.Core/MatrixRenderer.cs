using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Point = System.Windows.Point;

namespace AutoCommand.Matrix
{
    /// <summary>One falling stream inside a column: its head row and the
    /// glyph currently shown there. The wake is not drawn as part of the
    /// drop; each cell the head vacates becomes a fading WakeCell (over the
    /// etched backdrop) in instrument style, or a time-faded trail cell in
    /// cinema.</summary>
    internal sealed class RainDrop
    {
        public int Row;
        public int GlyphIndex;
        public bool Rx;
    }

    /// <summary>One character behind a lead (instrument style): its grid
    /// row, its glyph, and its current brightness. Brightness is stepped by
    /// DISTANCE behind the lead (same color family as the lead, one
    /// log-step dimmer per character) — never by time, so an idle stream
    /// freezes in place, animating only when events move it.</summary>
    internal sealed class WakeCell
    {
        public int Row;
        public int Glyph;
        public double Alpha;    // 0..1, recomputed while a lead anchors it
        public bool Rx;
    }

    /// <summary>One trail cell in cinema style: the glyph the lead stamped
    /// as it vacated the row, and when — the frame draws it at 0.28^(age),
    /// the same curve the bitmap engine's per-pixel fade pass produced,
    /// without owning a single pixel.</summary>
    internal sealed class CinemaCell
    {
        public int Row;
        public int Glyph;
        public double StampSec;
    }

    /// <summary>One trail cell of a decorative cinema stream.</summary>
    internal sealed class DecoCell
    {
        public int Row;
        public int Glyph;
        public double StampSec;
    }

    /// <summary>A decorative cinema stream — the movie's background rain:
    /// continuous, its own speed, its own brightness, restarting at the top
    /// after a breathing gap. Carries no data; it is the look.</summary>
    internal sealed class DecoStream
    {
        public double HeadRow;
        public double Speed;        // rows/sec
        public double WaitSec = -1; // >= 0: resting before restart
        public double Brightness;   // alpha scale for its green trail
        public int Glyph;
        public readonly List<DecoCell> Trail = new(96);
    }

    /// <summary>A rain column: the per-PID state the snapshots feed.</summary>
    internal sealed class RainColumn
    {
        public int Pid;
        public int Seq;                 // creation order — stable tiebreaker
        public string Name = "";
        public bool Blocked, Exited;
        /// <summary>The PID had at least one live conversation row in the
        /// latest snapshot — the pane carries exactly one column per such
        /// process, up to the under-ten cap.</summary>
        public bool Alive;
        public long LastTx, LastRx;
        public DateTime LastActivityUtc = DateTime.MinValue;
        public DateTime LastHeartbeatUtc = DateTime.MinValue;
        public DateTime MissingSinceUtc = DateTime.MinValue;
        public double Budget;           // letter credits: 1 letter = 1 row step
        public double RxBudget;
        /// <summary>Decaying transmit-activity score (recent TX packets
        /// plus blocked connection attempts) — drives the edge-anchored
        /// column ranking.</summary>
        public double Activity;
        public readonly List<RainDrop> Drops = new(4);
        public readonly List<WakeCell> Wake = new(32);
        /// <summary>Cinema trail: rows this column's leads stamped, fading
        /// by age. Ordered by stamp (front = oldest), so aging out is a
        /// front-trim.</summary>
        public readonly List<CinemaCell> CinemaTrail = new(128);
        /// <summary>Fractional fall-step accumulators: rows/sec sits below
        /// one row per frame at common rates (25/s at 60fps = 0.42 rows a
        /// frame), and flooring that per frame floors it to ZERO forever —
        /// the carry banks fractions and spends whole rows.</summary>
        public double FallCarryTx, FallCarryRx;
        public int Slot;
        public int PrevSlot = -1;               // last frame's slot — re-slot compensation
        public double XOffset;                  // DIP slide toward 0 (entrance / re-rank glide)
        public long TxBytes, RxBytes, TxPackets, RxPackets;
        public int Connections;
    }

    /// <summary>
    /// The rain itself, text-rendered in two stacked layers of a
    /// MatrixRainCanvas. The bottom layer is a dim ambient backdrop of
    /// glyphs — steady brightness, drifting down far slower than any
    /// stream. The top layer carries the falling streams: each stream is a
    /// LEAD glyph — the single brightest cell, zLift-scaled, shadowed,
    /// bloom-haloed — and its wake, the characters it has passed, each
    /// fading on a logarithmic curve (instrument: by trail distance, so an
    /// idle stream freezes; cinema: by age, the movie's silky tail) over
    /// the identical backdrop glyph etched beneath it.
    ///
    /// Every frame is REDRAWN FROM STATE as GlyphRuns: WPF owns
    /// rasterization, the glyph caches and every GPU resource — there is
    /// no WriteableBitmap, no Lock/AddDirtyRect bookkeeping, and a
    /// render-device loss (display sleep/wake, session lock, monitor
    /// change — the bitmap engine's three-time crash class, crash.log
    /// 2026-11-08/09/11) is absorbed inside WPF's composition, invisible
    /// to this loop. Sizing is DIP-native, so the per-DPI atlas rebuilds
    /// are gone too.
    ///
    /// Every TX packet buys one falling glyph step in that PID's column; a
    /// traffic-blocked PID spends its budget in red.
    /// </summary>
    public sealed class MatrixRenderer : IDisposable
    {
        private readonly MatrixRainCanvas _canvas;
        private readonly Func<IReadOnlyList<PidSnapshot>> _latestSource;
        private readonly Random _rand = new();

        private MatrixRainConfig _cfg;
        private GlyphCase _case;

        // Backdrop state: a per-cell glyph grid — FROZEN by default; the
        // only changes are real ones (falling wakes etching in) unless
        // drift is explicitly enabled. Redrawn only when dirty.
        private int[,] _ambientGrid;         // [col,row] glyph index, -1 = empty
        private int _ambientCols, _ambientRows;
        private double _driftAccumSec;
        private bool _ambientDirty;
        private readonly List<(int Slot, int Row, int Glyph)> _pendingEtches = new();

        private double _w, _h;           // DIPs
        private double _bandH;           // label band height (DIP)
        private int _gridCols, _gridRows;

        private readonly Dictionary<int, RainColumn> _columns = new();
        private List<RainColumn> _orderedColumns = new();   // activity-ranked, resort cadence below
        private double _resortAccumSec;
        private int _creationSeq;
        private IReadOnlyList<PidSnapshot> _consumed = Array.Empty<PidSnapshot>();
        /// <summary>Alive tracked processes in the latest snapshot — the
        /// column count IS this number (capped under ten); the wall spans
        /// exactly the columns the data occupies.</summary>
        private int _alivePidCount;
        private int _activeCols;

        private readonly Stopwatch _clock = Stopwatch.StartNew();
        private double _lastFrameSec;
        private bool _running;

        private const int MaxDropsPerColor = 3;
        private const int PidLabelRows = 6;   // PIDs up to 6 digits, vertically
        private const double ActivityDecayPerSnapshot = 0.97;  // ~2.3 s half-life at 100 ms snapshots
        private const double ResortSeconds = 2.0;
        /// <summary>Cinema trail lifetime: 0.28^t bottoms out just under
        /// the visibility threshold here (the fade curve the bitmap
        /// engine's per-pixel multiply produced).</summary>
        private const double TrailLifeSeconds = 4.4;
        /// <summary>Trail/wake alpha quantization: cells land in one of
        /// this many opacity classes so a whole class draws as one
        /// GlyphRun per owning typeface.</summary>
        private const int AlphaClasses = 12;

        // Log-fade curve over TRAIL DISTANCE: F(d) = ln(1 + k(D-d))/ln(9),
        // with k*D == 8 so the shape is constant whatever the length — the
        // char right behind the lead is ~full lead brightness, each further
        // character one log-step dimmer, gone at distance D.
        private const double WakeDenom = 1.0 / 2.1972245773362196;   // 1/ln(9)
        private double _wakeCharLength = 40;                          // D = wakeFadeSeconds x fallRowsPerSecond
        private double _wakeCurveK = 8.0 / 40;                        // 8 / D

        // Animation is EVENT-DRIVEN: re-ranking happens only after real
        // events (traffic, attempts, arrivals, retirements) — never on a
        // timer over decayed scores, which made idle columns shift.
        private bool _rankDirty;

        private bool _rainClearPending;   // full rain-layer reset (case rebuild, column retirement)

        public MatrixRenderer(MatrixRainCanvas canvas, Func<IReadOnlyList<PidSnapshot>> latest, MatrixRainConfig cfg)
        {
            _canvas = canvas;
            _latestSource = latest;
            _frameTimer.Tick += (s, e) => Frame(null, EventArgs.Empty);
            ApplyConfig(cfg);
        }

        /// <summary>Hot-applies config: font/color/charset changes rebuild
        /// the case; rates and caps take effect on the next frame.</summary>
        public void ApplyConfig(MatrixRainConfig cfg)
        {
            bool rebuild = _cfg == null || cfg.VisualsDifferFrom(_cfg);
            _cfg = cfg;
            if (rebuild || _case == null)
            {
                _case = GlyphCase.Build(cfg);
                // Cell metrics changed — stale trails would smear; reset.
                _rainClearPending = true;
            }
            // Trail length in characters: the configured wake lifetime at
            // the current fall speed.
            _wakeCharLength = Math.Clamp(cfg.WakeFadeSeconds * cfg.FallRowsPerSecond, 8, 80);
            _wakeCurveK = 8.0 / _wakeCharLength;
            RecomputeGrid();
        }

        // ------------------------------------------------------------------
        // Layout
        // ------------------------------------------------------------------

        /// <summary>(Re)sizes the rain surface, in DIPs — WPF owns device
        /// pixels, so no per-DPI atlas rebuild, no surface recreation; the
        /// grid just re-derives from the new cell counts.</summary>
        public void SetSurfaceSize(double dipWidth, double dipHeight)
        {
            double w = Math.Max(1, dipWidth), h = Math.Max(1, dipHeight);
            if (w == _w && h == _h && _case != null) return;

            _w = w; _h = h;
            _rainClearPending = true;
            RecomputeGrid();
        }

        private void RecomputeGrid()
        {
            if (_case == null || _w == 0 || _h == 0) return;
            _bandH = _cfg.ShowLabels ? 3 + PidLabelRows * _case.LabelCellH + 3 : 0;
            _gridCols = Math.Max(1, (int)(_w / _case.CellW));
            _gridRows = Math.Max(1, (int)((_h - _bandH) / _case.CellH));
            // the deco wall is sized to the ALIVE column count every frame
            // (see Frame) — not to the grid width: the pane carries exactly
            // as many columns as there are alive processes
            UpdateActiveColumns();
            RebuildAmbientGrid();
        }

        /// <summary>The decorative wall spans exactly the data columns —
        /// _activeCols of them, hugging the docked edge. Resized whenever
        /// the alive count or the grid changes; the fade decays any wall
        /// left outside the region.</summary>
        private void SyncDecoWall()
        {
            if (!Cinema) { _deco = Array.Empty<DecoStream>(); return; }
            int n = Math.Min(_activeCols, _gridCols);
            if (_deco.Length == n) return;
            int glyphs = _case.GlyphChars.Length;
            var old = _deco;
            _deco = new DecoStream[n];
            for (int c = 0; c < n; c++)
            {
                if (c < old.Length) { _deco[c] = old[c]; continue; }  // keep falling streams
                _deco[c] = new DecoStream
                {
                    HeadRow = _rand.Next(-20, _gridRows),
                    Speed = 9 + _rand.NextDouble() * 17,
                    Brightness = 0.85 + _rand.NextDouble() * 0.15,
                    Glyph = _rand.Next(glyphs),
                    WaitSec = _rand.NextDouble() < 0.10 ? _rand.NextDouble() * 0.8 : -1
                };
            }
        }

        /// <summary>Cinema style: the movie's wall of rain. Instrument
        /// style is the event-driven stillness.</summary>
        private bool Cinema => _cfg.Style == "cinema";
        private DecoStream[] _deco = Array.Empty<DecoStream>();

        public void Start()
        {
            if (_running) return;
            _running = true;
            _lastFrameSec = _clock.Elapsed.TotalSeconds;
            _frameTimer.Start();
        }

        public void Stop()
        {
            if (!_running) return;
            _running = false;
            _frameTimer.Stop();
        }

        // DispatcherTimer, NOT CompositionTarget.Rendering: the composition
        // event only fires when the visual tree invalidates, and this loop
        // is its own invalidator — one early-out starves the chain and the
        // rain never starts. A timer ticks regardless.
        private readonly System.Windows.Threading.DispatcherTimer _frameTimer =
            new(System.Windows.Threading.DispatcherPriority.Render)
            {
                Interval = TimeSpan.FromMilliseconds(15)
            };

        public int LiveColumns => _columns.Count;
        public double LastFps => _fpsEma;
        public int SurfaceWidth => (int)_w;
        public int SurfaceHeight => (int)_h;
        private double _fpsEma;
        /// <summary>Glyph cells drawn in the last frame.</summary>
        public long DebugDraws;
        /// <summary>Timer ticks skipped by the frame-rate cap (the surface
        /// already has its frames).</summary>
        public long DebugDrops;
        /// <summary>0..1 — the fraction of the 15 ms tick budget left after
        /// the last frame's draw.</summary>
        public double DebugBudget;

        /// <summary>The alive, capped column count — the host panel sizes
        /// itself to exactly this many cells, so the pane carries no gap
        /// strip beside the rain.</summary>
        public int ActiveColumns => _activeCols;

        /// <summary>One cell's width in DIP (the whole renderer works in
        /// DIPs — WPF scales to the device).</summary>
        public double CellWidthDip => _case == null ? 0 : _case.CellW;

        /// <summary>Raised on the UI thread when the alive-column count or
        /// the cell metrics change.</summary>
        public event Action ActiveColumnsChanged;

        private void UpdateActiveColumns()
        {
            int n = Math.Min(_alivePidCount, Math.Min(_cfg.MaxColumns, _gridCols));
            if (n == _activeCols) return;
            _activeCols = n;
            ActiveColumnsChanged?.Invoke();
        }

        // ------------------------------------------------------------------
        // Frame
        // ------------------------------------------------------------------

        private void Frame(object sender, EventArgs e)
        {
            if (_case == null || _w <= 0 || _h <= 0) return;

            double now = _clock.Elapsed.TotalSeconds;
            double dt = now - _lastFrameSec;

            // Big surfaces (the full-desktop dock) render at 30 fps —
            // twice the work every vsync buys nothing visually.
            int fps = _w * _h > 1_500_000 ? 30 : 60;
            if (dt < 1.0 / fps - 0.0005) { DebugDrops++; return; }
            _lastFrameSec = now;
            dt = Math.Clamp(dt, 0.001, 0.25);
            _fpsEma = _fpsEma <= 0 ? 1.0 / dt : _fpsEma * 0.9 + (1.0 / dt) * 0.1;

            ConsumeSnapshot();
            UpdateActiveColumns();
            if (Cinema) SyncDecoWall();
            Simulate(now, dt);

            var sw = Stopwatch.StartNew();
            using (var dc = _canvas.OpenRain())
                DrawRain(dc, now);

            if (!Cinema && _pendingEtches.Count > 0)
                ApplyPendingEtches();
            TickAmbient(dt);

            if (_ambientDirty)
            {
                _ambientDirty = false;
                using (var adc = _canvas.OpenAmbient())
                    DrawAmbient(adc);
            }
            sw.Stop();
            DebugBudget = Math.Clamp(1.0 - sw.Elapsed.TotalMilliseconds / 15.0, 0.0, 1.0);
        }

        // ------------------------------------------------------------------
        // Simulation — the state the draw pass renders
        // ------------------------------------------------------------------

        private void Simulate(double nowSec, double dt)
        {
            // Re-rank only after REAL events (traffic, attempts,
            // arrivals, retirements) — an idle pane is a still pane;
            // decayed scores never shuffle columns on their own. The
            // 2 s cadence just paces how promptly event-driven
            // promotions animate.
            _resortAccumSec += dt;
            if (_orderedColumns.Count == 0 || (_rankDirty && _resortAccumSec >= ResortSeconds))
            {
                _resortAccumSec = 0;
                _rankDirty = false;
                _orderedColumns = _columns.Values
                    .OrderByDescending(c => c.Activity)
                    .ThenBy(c => c.Seq)
                    .ToList();
            }

            // Edge-anchored slots: the most-active column hugs the edge
            // the pane is docked against — rightmost when docked right,
            // leftmost when docked left — and the pane carries exactly
            // ALIVE-count columns (never more than the under-ten cap):
            // an IP leaves the monitor's table, its column leaves the
            // pane. Etched wakes belong to grid cells, so a head that
            // changes columns leaves its old wake behind as ordinary
            // backdrop.
            int maxSlots = Math.Min(_alivePidCount, Math.Min(_cfg.MaxColumns, _gridCols));
            bool busiestAtLeft = _cfg.Dock == "left";

            int idx = 0;
            foreach (var col in _orderedColumns)
            {
                if (!_columns.TryGetValue(col.Pid, out var cur) || !cur.Alive) continue;
                if (idx >= maxSlots)
                {
                    // beyond the alive cap: no slot this frame. There is no
                    // strip to wipe — the pane redraws from state, and an
                    // unslotted column simply is not drawn.
                    if (cur.PrevSlot >= 0) { cur.Slot = -1; cur.PrevSlot = -1; }
                    continue;
                }
                int newSlot = busiestAtLeft ? idx : _gridCols - 1 - idx;
                idx++;

                if (col.PrevSlot < 0)
                {
                    // A new id: its column slides OUT from the docked
                    // edge into place instead of popping into existence.
                    col.XOffset = busiestAtLeft
                        ? -(newSlot * _case.CellW)
                        : _w - newSlot * _case.CellW;
                }
                else if (col.PrevSlot != newSlot)
                {
                    // Re-ranked: compensate so the rendered position is
                    // continuous, then glide to the new slot.
                    col.XOffset += (col.PrevSlot - newSlot) * _case.CellW;
                }
                col.PrevSlot = newSlot;
                col.Slot = newSlot;

                StepColumn(col, dt, nowSec);
            }

            if (Cinema) StepDeco(dt, nowSec);
        }

        private void StepColumn(RainColumn col, double dt, double nowSec)
        {
            // No synthetic animation: blocked-but-silent columns simply ARE
            // (red label, frozen stream) — they animate again on real
            // connection attempts. Easing of an event's slide continues:

            // Entrance / re-rank glide: ease the slide toward rest.
            if (col.XOffset != 0)
            {
                col.XOffset *= Math.Exp(-dt * 6.0);
                if (Math.Abs(col.XOffset) < 0.75) col.XOffset = 0;
            }

            if (!col.Exited)
            {
                // Fall-speed ceiling, rows/sec, FRACTIONAL by accumulation:
                // 25 rows/s at 60fps is 0.42 rows per frame — an integer
                // cast of that is 0 every frame and the rain never falls.
                // The carry banks fractions and spends whole rows.
                col.FallCarryTx += dt * _cfg.FallRowsPerSecond;
                int capTx = (int)col.FallCarryTx;
                col.FallCarryTx -= capTx;
                StepDrops(col, capTx, rx: false, nowSec);

                if (_cfg.RxMode)
                {
                    col.FallCarryRx += dt * _cfg.FallRowsPerSecond * 0.5;
                    int capRx = (int)col.FallCarryRx;
                    col.FallCarryRx -= capRx;
                    StepDrops(col, capRx, rx: true, nowSec);
                }
            }

            // Cinema trails age out from the front (oldest stamp first).
            while (col.CinemaTrail.Count > 0 && nowSec - col.CinemaTrail[0].StampSec > TrailLifeSeconds)
                col.CinemaTrail.RemoveAt(0);
        }

        private void StepDrops(RainColumn col, int maxAdvance, bool rx, double nowSec)
        {
            double budget = Math.Min(rx ? col.RxBudget : col.Budget, 600);
            int glyphCount = _case.GlyphChars.Length;
            int sameColor = 0;
            for (int i = col.Drops.Count - 1; i >= 0; i--)
                if (col.Drops[i].Rx == rx) sameColor++;

            if (budget >= 1.0 && sameColor < MaxDropsPerColor &&
                (sameColor == 0 || budget > 30))
            {
                col.Drops.Add(new RainDrop { Row = -1, Rx = rx, GlyphIndex = _rand.Next(glyphCount) });
                budget -= 1.0;
            }

            // Only the newest drop of each color carries the budget — traffic
            // is the story, and one live head per burst tells it.
            RainDrop lead = null;
            for (int i = col.Drops.Count - 1; i >= 0; i--)
                if (col.Drops[i].Rx == rx) { lead = col.Drops[i]; break; }

            int advance = lead == null ? 0 : (int)Math.Min(Math.Floor(budget), maxAdvance);
            budget -= advance;

            if (advance > 0)
            {
                for (int i = 0; i < advance; i++)
                {
                    if (lead.Row >= 0)
                    {
                        if (Cinema)
                        {
                            // the vacated character begins its time-faded
                            // life — the frame loop draws it at 0.28^age,
                            // the movie's silky tail
                            col.CinemaTrail.Add(new CinemaCell
                            {
                                Row = lead.Row,
                                Glyph = lead.GlyphIndex,
                                StampSec = nowSec
                            });
                        }
                        else
                        {
                            // The vacated character begins its logarithmic
                            // distance-fade — drawn over the identical
                            // backdrop glyph etched beneath it, so the
                            // completed fade resolves into a background
                            // character.
                            if (_cfg.Ambient && _ambientGrid != null)
                                _pendingEtches.Add((col.Slot, lead.Row, lead.GlyphIndex));
                            col.Wake.Add(new WakeCell
                            {
                                Row = lead.Row,
                                Glyph = lead.GlyphIndex,
                                Rx = rx
                            });
                        }
                    }
                    lead.Row++;
                    if (lead.Row >= _gridRows)
                    {
                        col.Drops.Remove(lead);
                        break;
                    }
                    // A fresh character takes the lead position.
                    lead.GlyphIndex = _rand.Next(glyphCount);
                }
            }

            if (rx) col.RxBudget = budget;
            else col.Budget = budget;
        }

        /// <summary>The decorative wall of rain: one continuous stream per
        /// grid column, own speed and brightness, restarting at the top
        /// after a breathing gap — green trails, white tips, occasional
        /// mid-trail glyph mutation, exactly the film's texture. Carries no
        /// data; the PID columns fall over it brighter and bloomed.</summary>
        private void StepDeco(double dt, double nowSec)
        {
            int n = _case.GlyphChars.Length;

            for (int c = 0; c < _deco.Length && c < _gridCols; c++)
            {
                var s = _deco[c];
                // the wall lives exactly where the data does: the alive
                // columns hugging the docked edge
                int edge = _cfg.Dock == "left" ? 0 : _gridCols - _deco.Length;
                double x = (edge + c) * _case.CellW;
                if (x + _case.CellW > _w) break;

                if (s.WaitSec >= 0)
                {
                    s.WaitSec -= dt;
                    if (s.WaitSec < 0)
                    {
                        s.HeadRow = -_rand.NextDouble() * 12;
                        s.Speed = 9 + _rand.NextDouble() * 17;
                        s.Brightness = 0.85 + _rand.NextDouble() * 0.15;
                        s.Glyph = _rand.Next(n);
                        s.Trail.Clear();
                    }
                    continue;
                }

                int prevRow = (int)s.HeadRow;
                s.HeadRow += s.Speed * dt;
                int newRow = (int)s.HeadRow;

                if (newRow >= _gridRows + 6)
                {
                    s.WaitSec = _rand.NextDouble() * 0.8;
                    continue;
                }

                // green where the head has crossed
                for (int r = Math.Max(0, prevRow + 1); r <= newRow && r < _gridRows; r++)
                    s.Trail.Add(new DecoCell { Row = r, Glyph = _rand.Next(n), StampSec = nowSec });

                // mid-trail mutation — the film's shimmer: the cell gets a
                // fresh glyph and a fresh stamp, moved to the trail's end
                // to keep the front-aging order.
                if (newRow > 4 && _rand.NextDouble() < 0.12)
                {
                    int mr = newRow - _rand.Next(1, Math.Min(16, newRow));
                    if (mr >= 0 && RestampDeco(s, mr, nowSec) == null)
                        s.Trail.Add(new DecoCell { Row = mr, Glyph = _rand.Next(n), StampSec = nowSec });
                }

                // the trail ages out from the front (oldest stamp first)
                while (s.Trail.Count > 0 && nowSec - s.Trail[0].StampSec > TrailLifeSeconds)
                    s.Trail.RemoveAt(0);
            }
        }

        /// <summary>Re-stamps an existing trail cell (mutation shimmer):
        /// fresh stamp, moved to the list's end. Returns the moved cell, or
        /// null if that row carries no cell yet.</summary>
        private static DecoCell RestampDeco(DecoStream s, int row, double nowSec)
        {
            for (int i = 0; i < s.Trail.Count; i++)
                if (s.Trail[i].Row == row)
                {
                    var cell = s.Trail[i];
                    s.Trail.RemoveAt(i);
                    s.Trail.Add(cell);
                    cell.StampSec = nowSec;
                    return cell;
                }
            return null;
        }

        /// <summary>A new snapshot from the engine: convert absolute counter
        /// movement into letter budgets, create/retire columns. Snapshots are
        /// immutable and counters absolute, so a skipped one loses nothing.</summary>
        private void ConsumeSnapshot()
        {
            var snap = _latestSource();
            if (ReferenceEquals(snap, _consumed)) return;
            _consumed = snap;

            int cap = Math.Min(Math.Max(1, _cfg.MaxColumns), _gridCols);
            var now = DateTime.UtcNow;
            var seen = new HashSet<int>();
            _alivePidCount = 0;

            foreach (var p in snap)
            {
                seen.Add(p.Pid);
                if (!p.Exited) _alivePidCount++;
                if (!_columns.TryGetValue(p.Pid, out var col))
                {
                    // At cap, a newcomer takes over the stalest idle column.
                    if (_columns.Count >= cap)
                    {
                        RainColumn stalest = null;
                        foreach (var c in _columns.Values)
                            if (stalest == null || c.LastActivityUtc < stalest.LastActivityUtc)
                                stalest = c;
                        if (stalest == null || (now - stalest.LastActivityUtc).TotalSeconds < 30)
                            continue; // everyone is busy — the PID gets no column yet
                        _columns.Remove(stalest.Pid);
                        _rainClearPending = true;
                        _rankDirty = true;
                    }
                    col = new RainColumn
                    {
                        Pid = p.Pid,
                        Seq = _creationSeq++,
                        LastTx = p.TxPackets,
                        LastRx = p.RxPackets
                    };
                    _columns[p.Pid] = col;
                    _orderedColumns.Add(col);   // ranked properly at the next re-sort
                    _rankDirty = true;
                }

                col.Name = p.Name;
                col.Blocked = p.Blocked;
                col.Exited = p.Exited;
                col.Alive = true;
                col.TxBytes = p.TxBytes; col.RxBytes = p.RxBytes;
                col.TxPackets = p.TxPackets; col.RxPackets = p.RxPackets;
                col.Connections = p.Connections;
                col.MissingSinceUtc = DateTime.MinValue;

                long dTx = p.TxPackets - col.LastTx;
                long dRx = p.RxPackets - col.LastRx;

                // Edge-anchored ranking: recent transmits (and, for blocked
                // PIDs, connection attempts) on a decaying score — the
                // busiest column lives at the docked edge. Only real events
                // dirty the ranking.
                col.Activity = col.Activity * ActivityDecayPerSnapshot
                             + Math.Max(0, dTx)
                             + (p.Blocked ? p.Attempts : 0);
                if (dTx > 0 || p.Attempts > 0) _rankDirty = true;

                if (dTx > 0) col.Budget = Math.Min(col.Budget + dTx * _cfg.LettersPerTransmit, 600);
                if (dRx > 0 && _cfg.RxMode) col.RxBudget = Math.Min(col.RxBudget + dRx * _cfg.LettersPerTransmit, 600);
                // A backwards jump means the counter restarted (new row set on
                // PID reuse) — re-anchor instead of flooding letters.

                // While blocked, the sniffer sees nothing (the firewall drops
                // the packet before the wire) — each fresh connection attempt
                // still rolls red.
                if (p.Blocked && p.Attempts > 0)
                    col.Budget = Math.Min(col.Budget + p.Attempts * Math.Max(1.0, _cfg.LettersPerTransmit), 600);

                if (dTx > 0 || p.Attempts > 0) col.LastActivityUtc = now;
                col.LastTx = p.TxPackets;
                col.LastRx = p.RxPackets;
            }

            // Columns whose PID stayed absent — exited, or the row was handed
            // to a new PID — retire softly: residues keep decaying on their own.
            foreach (var pid in _columns.Keys.ToArray())
            {
                var col = _columns[pid];
                if (seen.Contains(pid)) continue;
                if (col.MissingSinceUtc == DateTime.MinValue) col.MissingSinceUtc = now;
                col.Alive = false;
                if ((now - col.MissingSinceUtc).TotalSeconds > 12)
                {
                    _columns.Remove(pid);
                    _rainClearPending = true;
                    _rankDirty = true;
                }
            }
        }

        // ------------------------------------------------------------------
        // Drawing — state to GlyphRuns, every frame, nothing retained
        // ------------------------------------------------------------------

        private long _frameDraws;

        private void DrawRain(DrawingContext dc, double nowSec)
        {
            if (_rainClearPending)
            {
                foreach (var c in _columns.Values) c.CinemaTrail.Clear();
                foreach (var d in _deco) d.Trail.Clear();
                _rainClearPending = false;
            }

            _frameDraws = 0;

            if (Cinema) DrawCinemaTrails(dc, nowSec);
            else DrawInstrumentWake(dc);

            DrawLabels(dc);
            DrawHeads(dc);

            DebugDraws = _frameDraws;
        }

        /// <summary>Dim layers first, bright heads last — the movie's depth.
        /// Trail cells fade by age (0.28^t, the fade pass's curve); alpha
        /// quantizes into classes so each class draws as one GlyphRun per
        /// owning typeface.</summary>
        private void DrawCinemaTrails(DrawingContext dc, double nowSec)
        {
            double ppd = _canvas.PixelsPerDip;
            var batches = new Dictionary<(Brush brush, int cls), GlyphBatch>();
            const double fadeBase = 0.28;

            // the wall
            int edge = _cfg.Dock == "left" ? 0 : _gridCols - _deco.Length;
            for (int c = 0; c < _deco.Length && c < _gridCols; c++)
            {
                double x = (edge + c) * _case.CellW;
                if (x + _case.CellW > _w) break;
                var s = _deco[c];
                foreach (var cell in s.Trail)
                {
                    if (cell.Row < 0 || cell.Row >= _gridRows) continue;
                    double alpha = Math.Pow(fadeBase, nowSec - cell.StampSec) * s.Brightness;
                    AddTrailCell(batches, x, cell.Row, cell.Glyph, alpha, _case.Trail, ppd);
                }
            }

            // the data streams over it
            foreach (var col in _columns.Values)
            {
                double x = ColumnX(col);
                if (col.Slot < 0 || x < 0 || x + _case.CellW > _w) continue;
                foreach (var cell in col.CinemaTrail)
                {
                    if (cell.Row < 0 || cell.Row >= _gridRows) continue;
                    double alpha = Math.Pow(fadeBase, nowSec - cell.StampSec);
                    AddTrailCell(batches, x, cell.Row, cell.Glyph, alpha, _case.Trail, ppd);
                }
            }

            FlushBatches(dc, batches);
        }

        private void AddTrailCell(Dictionary<(Brush, int), GlyphBatch> batches,
            double x, int row, int glyph, double alpha, Brush brush, double ppd)
        {
            if (alpha <= 0.008) return;
            int cls = (int)Math.Clamp(alpha * AlphaClasses, 0, AlphaClasses - 1);
            if (!batches.TryGetValue((brush, cls), out var b))
                batches[(brush, cls)] = b = new GlyphBatch(_case.Em, ppd);
            PlaceGlyph(b, glyph, x, _bandH + row * _case.CellH, _case.CellW, _case.CellH, _case.Em);
        }

        /// <summary>Instrument wake: characters behind the lead — same
        /// brightness family as the lead, dimmer incrementally by distance.
        /// Idle streams freeze: with no lead the staircase keeps its last
        /// alpha. Outlived cells leave the list here (the draw pass is the
        /// only place distances are known).</summary>
        private void DrawInstrumentWake(DrawingContext dc)
        {
            double ppd = _canvas.PixelsPerDip;
            var batches = new Dictionary<(Brush, int), GlyphBatch>();

            foreach (var col in _columns.Values)
            {
                double x = ColumnX(col);
                if (col.Slot < 0 || x < 0 || x + _case.CellW > _w) continue;

                // The lead row of each color anchors its wake's distances.
                int leadTx = -1, leadRx = -1;
                for (int i = 0; i < col.Drops.Count; i++)
                {
                    var d = col.Drops[i];
                    if (d.Row < 0) continue;
                    if (d.Rx) { if (d.Row > leadRx) leadRx = d.Row; }
                    else { if (d.Row > leadTx) leadTx = d.Row; }
                }

                for (int i = col.Wake.Count - 1; i >= 0; i--)
                {
                    var w = col.Wake[i];
                    int anchor = w.Rx ? leadRx : leadTx;
                    if (anchor >= 0)
                    {
                        int dist = anchor - w.Row;
                        if (dist > _wakeCharLength || w.Row < 0 || w.Row >= _gridRows)
                        {
                            col.Wake.RemoveAt(i);
                            continue;
                        }
                        w.Alpha = WakeAlphaByDistance(dist);
                    }
                    if (w.Alpha <= 0.004) continue;

                    var brush = w.Rx ? _case.Rx : col.Blocked ? _case.BlockedHead : _case.Head;
                    int cls = (int)Math.Clamp(w.Alpha * AlphaClasses, 0, AlphaClasses - 1);
                    if (!batches.TryGetValue((brush, cls), out var b))
                        batches[(brush, cls)] = b = new GlyphBatch(_case.Em, ppd);
                    PlaceGlyph(b, w.Glyph, x, _bandH + w.Row * _case.CellH, _case.CellW, _case.CellH, _case.Em);
                }
            }

            FlushBatches(dc, batches);
        }

        /// <summary>The PID reads vertically down its column — a rain column
        /// is one glyph wide, so sideways labels would spill into the
        /// neighbor's rain. Blocked PIDs read their digits red.</summary>
        private void DrawLabels(DrawingContext dc)
        {
            if (!_cfg.ShowLabels) return;

            var normal = new GlyphBatch(_case.LabelEm, _canvas.PixelsPerDip);
            var blocked = new GlyphBatch(_case.LabelEm, _canvas.PixelsPerDip);
            int n = 0, bCount = 0;

            foreach (var col in _columns.Values)
            {
                if (col.Slot < 0) continue;
                double x = ColumnX(col) + Math.Max(0, (_case.CellW - _case.LabelCellW) / 2);
                if (x < 0) continue;

                string digits = col.Pid.ToString();
                if (digits.Length > PidLabelRows) digits = digits.Substring(digits.Length - PidLabelRows);

                var batch = col.Blocked ? blocked : normal;
                for (int i = 0; i < digits.Length; i++)
                {
                    int d = digits[i] - '0';
                    var f = _case.Digits[d];
                    batch.Add(f,
                        x + (_case.LabelCellW - f.Advance) / 2,
                        3 + i * _case.LabelCellH + _case.LabelCellH * 0.5 + _case.LabelEm * 0.36);
                    if (col.Blocked) bCount++; else n++;
                }
            }

            if (n > 0) { normal.Flush(dc, _case.Label); _frameDraws += n; }
            if (bCount > 0) { blocked.Flush(dc, _case.LabelBlocked); _frameDraws += bCount; }
        }

        /// <summary>The lead glyphs — the single brightest cells: bloom
        /// halo, the zLift shadow (instrument), the crisp glyph on top. In
        /// cinema the decorative wall's white tips ride along.</summary>
        private void DrawHeads(DrawingContext dc)
        {
            double ppd = _canvas.PixelsPerDip;

            if (Cinema)
            {
                // the wall's white tips
                int edge = _cfg.Dock == "left" ? 0 : _gridCols - _deco.Length;
                var tipBatch = new GlyphBatch(_case.Em, ppd);
                int tips = 0;
                for (int c = 0; c < _deco.Length && c < _gridCols; c++)
                {
                    double x = (edge + c) * _case.CellW;
                    if (x + _case.CellW > _w) break;
                    var s = _deco[c];
                    int row = (int)s.HeadRow;
                    if (s.WaitSec >= 0 || row < 0 || row >= _gridRows) continue;
                    PlaceGlyph(tipBatch, s.Glyph, x, _bandH + row * _case.CellH, _case.CellW, _case.CellH, _case.Em);
                    tips++;
                }
                if (tips > 0)
                {
                    dc.PushOpacity(244.0 / 255.0);
                    tipBatch.Flush(dc, _case.Head);
                    dc.Pop();
                    _frameDraws += tips;
                }
            }

            foreach (var col in _columns.Values)
            {
                if (col.Slot < 0) continue;
                double x = ColumnX(col);
                if (x < 0 || x + _case.CellW > _w) continue;
                for (int i = col.Drops.Count - 1; i >= 0; i--)
                    DrawHead(dc, col, col.Drops[i], x, ppd);
            }
        }

        private void DrawHead(DrawingContext dc, RainColumn col, RainDrop d, double x, double ppd)
        {
            if (d.Row < 0 || d.Row >= _gridRows) return;

            double em = _case.LiftEm;
            double scale = em / _case.Em;
            double cw = _case.CellW * scale, ch = _case.CellH * scale;
            double gx = x + (_case.CellW - cw) / 2;
            double gy = _bandH + d.Row * _case.CellH + (_case.CellH - ch) / 2;

            Brush head = d.Rx ? _case.Rx : col.Blocked ? _case.BlockedHead : _case.Head;
            Brush bloom = d.Rx ? _case.RxBloom : col.Blocked ? _case.BlockedHeadBloom : _case.HeadBloom;

            // depth first (instrument), glow second, the crisp glyph on top
            if (!Cinema && _case.Shadow != null)
            {
                int so = Math.Max(1, (int)((cw - _case.CellW) / 2));
                var sb = new GlyphBatch(em, ppd);
                PlaceGlyph(sb, d.GlyphIndex, gx + so, gy + so + 1, cw, ch, em);
                sb.Flush(dc, _case.Shadow);
            }
            if (bloom != null)
                dc.DrawEllipse(bloom, null, new Point(gx + cw / 2, gy + ch / 2), cw * 0.65, ch * 0.65);

            var b = new GlyphBatch(em, ppd);
            PlaceGlyph(b, d.GlyphIndex, gx, gy, cw, ch, em);
            b.Flush(dc, head);
            _frameDraws++;
        }

        /// <summary>Places a charset glyph centered in a cell: horizontal by
        /// advance, vertical by baseline at the em's cap-middle.</summary>
        private void PlaceGlyph(GlyphBatch b, int glyph, double cellLeft, double cellTop,
            double cellW, double cellH, double em)
        {
            var f = _case.Faces[glyph];
            double adv = f.Advance * (em / _case.Em);
            b.Add(f,
                cellLeft + (cellW - adv) / 2,
                cellTop + cellH * 0.5 + em * 0.36);
        }

        private static void FlushBatches(DrawingContext dc, Dictionary<(Brush brush, int cls), GlyphBatch> batches)
        {
            foreach (var kv in batches)
            {
                dc.PushOpacity((kv.Key.cls + 0.5) / AlphaClasses);
                kv.Value.Flush(dc, kv.Key.brush);
                dc.Pop();
            }
        }

        /// <summary>Incremental dimming by TRAIL DISTANCE — the character
        /// right behind the lead is ~full lead brightness (same color
        /// family, capped a hair under so the lead stays strictly
        /// brightest), each further character one log-step dimmer, gone at
        /// the trail length.</summary>
        private double WakeAlphaByDistance(int dist)
        {
            double d = _wakeCharLength;
            if (dist < 0) dist = 0;
            if (dist >= d) return 0;
            double f = Math.Log(1 + _wakeCurveK * (d - dist)) * WakeDenom;
            return Math.Clamp(f, 0, 1) * (248.0 / 256.0);
        }

        /// <summary>The column's x this frame: its slot plus any slide
        /// offset still easing toward rest.</summary>
        private double ColumnX(RainColumn col) =>
            col.Slot * _case.CellW + col.XOffset;

        // ------------------------------------------------------------------
        // Ambient backdrop — the slow, steady-brightness glyph field
        // ------------------------------------------------------------------

        /// <summary>(Re)builds the backdrop grid after a resize or a case
        /// rebuild; disabled ambient clears its layer.</summary>
        private void RebuildAmbientGrid()
        {
            if (Cinema || !_cfg.Ambient)
            {
                // Cinema is pure black behind the rain — the movie has no
                // backdrop field.
                _ambientGrid = null;
                _ambientDirty = true;
                return;
            }

            _ambientCols = Math.Max(1, (int)(_w / _case.CellW));
            _ambientRows = Math.Max(1, (int)((_h - _bandH) / _case.CellH));
            _ambientGrid = new int[_ambientCols, _ambientRows];
            for (int c = 0; c < _ambientCols; c++)
                for (int r = 0; r < _ambientRows; r++)
                    _ambientGrid[c, r] = _rand.NextDouble() <= _cfg.AmbientDensity
                        ? _rand.Next(_case.GlyphChars.Length) : -1;
            _ambientDirty = true;
        }

        private void DrawAmbient(DrawingContext dc)
        {
            if (_ambientGrid == null) return;
            var b = new GlyphBatch(_case.Em, _canvas.PixelsPerDip);
            for (int c = 0; c < _ambientCols; c++)
                for (int r = 0; r < _ambientRows; r++)
                {
                    int idx = _ambientGrid[c, r];
                    if (idx < 0) continue;
                    PlaceGlyph(b, idx, c * _case.CellW, _bandH + r * _case.CellH, _case.CellW, _case.CellH, _case.Em);
                }
            b.Flush(dc, _case.Ambient);
        }

        /// <summary>Writes this frame's wake into the backdrop: each cell a
        /// lead glyph vacated takes that glyph as a steady ambient
        /// character — from here on it is indistinguishable from the
        /// background field (same color, same size, and it drifts and
        /// mutates with the field like every other backdrop cell).</summary>
        private void ApplyPendingEtches()
        {
            if (_ambientGrid == null) { _pendingEtches.Clear(); return; }
            foreach (var (slot, row, glyph) in _pendingEtches)
                if (slot >= 0 && slot < _ambientCols && row >= 0 && row < _ambientRows)
                    _ambientGrid[slot, row] = glyph;
            _pendingEtches.Clear();
            _ambientDirty = true;   // one full-layer redraw per etch batch
        }

        /// <summary>The backdrop's life — which is to say, almost none: by
        /// default it is FROZEN (ambientDriftSeconds 0). A background that
        /// randomly changes under the rain breaks the illusion; the only
        /// backdrop changes are real ones — falling wakes etching their
        /// characters in. Opt-in drift eases the whole field down one row
        /// at a time.</summary>
        private void TickAmbient(double dt)
        {
            if (!_cfg.Ambient || _ambientGrid == null) return;
            if (_cfg.AmbientDriftSeconds <= 0) return;

            _driftAccumSec += dt;
            if (_driftAccumSec < _cfg.AmbientDriftSeconds) return;
            _driftAccumSec = 0;

            for (int c = 0; c < _ambientCols; c++)
            {
                for (int r = _ambientRows - 1; r > 0; r--)
                    _ambientGrid[c, r] = _ambientGrid[c, r - 1];
                _ambientGrid[c, 0] = _rand.NextDouble() <= _cfg.AmbientDensity
                    ? _rand.Next(_case.GlyphChars.Length) : -1;
            }
            _ambientDirty = true;
        }

        // ------------------------------------------------------------------
        // Diagnostics
        // ------------------------------------------------------------------

        public void DumpRainPng(string path)
        {
            if (_case == null || _w <= 0 || _h <= 0) return;
            try
            {
                // One software render of the canvas (both layers) — no GPU
                // dependency, no lock protocol; the exact pixels on screen.
                var rtb = new RenderTargetBitmap(
                    (int)Math.Ceiling(_w), (int)Math.Ceiling(_h), 96, 96, PixelFormats.Pbgra32);
                rtb.Render(_canvas);
                rtb.Freeze();
                var enc = new PngBitmapEncoder();
                enc.Frames.Add(BitmapFrame.Create(rtb));
                using var fs = File.Create(path);
                enc.Save(fs);
            }
            catch { }
        }

        /// <summary>Human story of the column under a DIP x — the window
        /// turns it into a tooltip when the overlay takes mouse input.</summary>
        public string DescribeColumnAt(double dipX)
        {
            if (_case == null) return null;
            int slot = (int)(dipX / _case.CellW);
            foreach (var col in _columns.Values)
                if (col.Slot == slot)
                    return
                        $"PID {col.Pid}  {col.Name}\n" +
                        $"tx {col.TxPackets:N0} pkts / {FormatBytes(col.TxBytes)}   " +
                        $"rx {col.RxPackets:N0} pkts / {FormatBytes(col.RxBytes)}\n" +
                        $"{col.Connections} tracked connection(s)" +
                        (col.Blocked ? "\nBlocked - raining red" : "") +
                        (col.Exited ? "\nprocess exited" : "");
            return null;
        }

        private static string FormatBytes(long b) => b switch
        {
            >= 1 << 30 => $"{b / (double)(1 << 30):F1} GB",
            >= 1 << 20 => $"{b / (double)(1 << 20):F1} MB",
            >= 1 << 10 => $"{b / (double)(1 << 10):F1} KB",
            _ => $"{b} B"
        };

        public void Dispose() => Stop();
    }
}
