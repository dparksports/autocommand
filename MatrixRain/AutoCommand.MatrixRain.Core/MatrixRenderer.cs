using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Image = System.Windows.Controls.Image;

namespace AutoCommand.Matrix
{
    /// <summary>One falling stream inside a column: its head row and the
    /// glyph currently shown there (plus the row it was drawn at last
    /// frame — exact clearing, since there is no fade pass to eat stray
    /// halo pixels). The wake is not drawn as part of the drop; each cell
    /// the head vacates becomes a fading WakeCell over the etched
    /// backdrop.</summary>
    internal sealed class RainDrop
    {
        public int Row;
        public int LastRow = -1;
        public int GlyphIndex;
        public bool Rx;
    }

    /// <summary>One character behind a lead: its grid row, its glyph, and
    /// its current brightness. Brightness is stepped by DISTANCE behind the
    /// lead (same color family as the lead, one log-step dimmer per
    /// character) — never by time, so an idle stream freezes in place,
    /// animating only when events move it.</summary>
    internal sealed class WakeCell
    {
        public int Row;
        public int Glyph;
        public double Alpha;    // 0..1, recomputed while a lead anchors it
        public bool Rx;
    }

    /// <summary>A decorative cinema stream — the movie's background rain:
    /// continuous, its own speed, its own brightness, restarting at the
    /// top after a breathing gap. Carries no data; it is the look.</summary>
    internal sealed class DecoStream
    {
        public double HeadRow;
        public double Speed;        // rows/sec
        public double WaitSec = -1; // >= 0: resting before restart
        public double Brightness;   // alpha scale for its green trail
        public int Glyph;
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
        /// <summary>Fractional fall-step accumulators: rows/sec sits below
        /// one row per frame at common rates (25/s at 60fps = 0.42 rows a
        /// frame), and flooring that per frame floors it to ZERO forever —
        /// the carry banks fractions and spends whole rows.</summary>
        public double FallCarryTx, FallCarryRx;
        public int Slot;
        public int PrevSlot = -1;               // last frame's slot — re-slot compensation
        public double XOffset;                  // device-px slide toward 0 (entrance / re-rank glide)
        public double LastDrawnX = double.MinValue;  // where the column rendered last frame (ghost clearing)
        public long TxBytes, RxBytes, TxPackets, RxPackets;
        public int Connections;
    }

    /// <summary>
    /// The rain itself, in two stacked layers. The bottom layer is a dim
    /// ambient backdrop of glyphs — steady brightness, drifting down far
    /// slower than any stream. The top layer carries the falling streams:
    /// each stream is a LEAD glyph — the single brightest cell, zLift-
    /// scaled, shadowed, bloom-haloed — and its wake, the characters it has
    /// passed, each fading on a logarithmic curve (brightness holds high,
    /// then plunges) over the identical backdrop glyph etched beneath it,
    /// so every completed fade resolves into a background character. There
    /// is no per-pixel fade pass: decay is exact, per cell. Every TX packet
    /// buys one falling glyph step in that PID's column; a traffic-blocked
    /// PID spends its budget in red.
    /// </summary>
    public sealed class MatrixRenderer : IDisposable
    {
        private readonly Image _image;
        private readonly Image _ambientImage;
        private readonly Func<IReadOnlyList<PidSnapshot>> _latestSource;
        private readonly Random _rand = new();

        private MatrixRainConfig _cfg;
        private GlyphAtlas _atlas;
        private WriteableBitmap _bmp;
        private WriteableBitmap _bgBmp;      // the ambient backdrop layer

        // Backdrop state: a per-cell glyph grid — FROZEN by default; the
        // only changes are real ones (falling wakes etching in) unless
        // drift is explicitly enabled.
        private int[,] _ambientGrid;         // [col,row] glyph index, -1 = empty
        private int _ambientCols, _ambientRows;
        private double _driftAccumSec;
        private readonly List<(int Slot, int Row, int Glyph)> _pendingEtches = new();

        private int _w, _h;              // device pixels
        private int _bandH;              // label band height (device px)
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

        private bool _rainClearPending;   // full rain-layer reset (atlas rebuild, column retirement)

        public MatrixRenderer(Image ambientImage, Image rainImage, Func<IReadOnlyList<PidSnapshot>> latest, MatrixRainConfig cfg)
        {
            _ambientImage = ambientImage;
            _image = rainImage;
            _latestSource = latest;
            _frameTimer.Tick += (s, e) => Frame(null, EventArgs.Empty);
            ApplyConfig(cfg);
        }

        public GlyphAtlas Atlas => _atlas;

        /// <summary>Hot-applies config: font/color/charset changes rebuild
        /// the atlas; rates and caps take effect on the next frame.</summary>
        public void ApplyConfig(MatrixRainConfig cfg)
        {
            bool rebuild = _cfg == null || cfg.VisualsDifferFrom(_cfg);
            _cfg = cfg;
            if (rebuild || _atlas == null)
            {
                _atlas = GlyphAtlas.Build(cfg, DpiScale);
                // Cell metrics changed — stale pixels would smear; reset.
                _rainClearPending = true;
            }
            // Trail length in characters: the configured wake lifetime at
            // the current fall speed.
            _wakeCharLength = Math.Clamp(cfg.WakeFadeSeconds * cfg.FallRowsPerSecond, 8, 80);
            _wakeCurveK = 8.0 / _wakeCharLength;
            RecomputeGrid();
        }

        private double DpiScale
        {
            get
            {
                var src = PresentationSource.FromVisual(_image);
                return src?.CompositionTarget?.TransformToDevice.M11 ?? 1.0;
            }
        }

        /// <summary>(Re)sizes the rain surface to device pixels; called on
        /// load, dock changes and DPI changes.</summary>
        public void SetSurfaceSize(double dipWidth, double dipHeight)
        {
            double scale = DpiScale;

            // The atlas is typically first built before the window has a
            // presentation source (scale reads as 1.0) — rebuild it once the
            // real per-monitor scale is known, so glyph cells match the
            // surface pixel-for-pixel.
            if (_atlas != null && Math.Abs(scale - _atlas.BuiltWithScale) > 0.01)
            {
                _atlas = GlyphAtlas.Build(_cfg, scale);
                RecomputeGrid();
            }

            int w = Math.Max(1, (int)Math.Ceiling(dipWidth * scale));
            int h = Math.Max(1, (int)Math.Ceiling(dipHeight * scale));
            if (w == _w && h == _h && _bmp != null) return;

            _w = w; _h = h;
            _bmp = new WriteableBitmap(w, h, 96, 96, PixelFormats.Pbgra32, null);
            _image.Source = _bmp;
            _image.Stretch = Stretch.Fill;
            _bgBmp = new WriteableBitmap(w, h, 96, 96, PixelFormats.Pbgra32, null);
            _ambientImage.Source = _bgBmp;
            _ambientImage.Stretch = Stretch.Fill;
            RecomputeGrid();
        }

        /// <summary>
        /// Replaces both rain surfaces after a render-device loss (display
        /// sleep/wake, session lock, monitor mode change): WPF tears down the
        /// bitmaps' GPU textures and resets their lock bookkeeping, so the
        /// next Lock/Unlock throws InvalidOperationException. Same-size
        /// rebuild — grid geometry is unchanged; the rain layer starts from
        /// a clean slate and the ambient field repaints in full.
        /// </summary>
        private void RebuildSurfaces()
        {
            if (_rebuildingSurfaces || _w == 0 || _h == 0) return;
            // Reentrancy guard: the ambient repaint below locks/unlocks the
            // fresh bitmap, and if the device is STILL lost that unlock would
            // recurse into this method — bail instead and let the next tick
            // try again.
            _rebuildingSurfaces = true;
            try
            {
                _bmp = new WriteableBitmap(_w, _h, 96, 96, PixelFormats.Pbgra32, null);
                _image.Source = _bmp;
                _bgBmp = new WriteableBitmap(_w, _h, 96, 96, PixelFormats.Pbgra32, null);
                _ambientImage.Source = _bgBmp;
                _rainClearPending = true;
                RedrawAmbientFull();
            }
            finally { _rebuildingSurfaces = false; }
        }

        private bool _rebuildingSurfaces;

        /// <summary>Lock that tolerates the device-loss state: false means
        /// the surface was dead and has been replaced — callers skip this
        /// pass; the next tick draws into the fresh bitmap.</summary>
        private bool LockSurface(WriteableBitmap bmp)
        {
            try { bmp.Lock(); return true; }
            catch (InvalidOperationException) { RebuildSurfaces(); return false; }
        }

        /// <summary>Unlock twin of <see cref="LockSurface"/>: a device loss
        /// mid-pass resets the lock state, so the Unlock of a completed draw
        /// can be the call that discovers it.</summary>
        private void UnlockSurface(WriteableBitmap bmp)
        {
            try { bmp.Unlock(); }
            catch (InvalidOperationException) { RebuildSurfaces(); }
        }

        private void RecomputeGrid()
        {
            if (_atlas == null || _w == 0) return;
            _bandH = _cfg.ShowLabels ? 3 + PidLabelRows * _atlas.LabelCellH + 3 : 0;
            _gridCols = Math.Max(1, _w / _atlas.CellW);
            _gridRows = Math.Max(1, (_h - _bandH) / _atlas.CellH);
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
            int glyphs = _atlas.GlyphChars.Length;
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
        public int SurfaceWidth => _w;
        public int SurfaceHeight => _h;
        public long DebugDraws;
        public int DebugDrops;
        public double DebugBudget;
        private double _fpsEma;

        /// <summary>The alive, capped column count — the host panel sizes
        /// itself to exactly this many cells, so the pane carries no gap
        /// strip beside the rain.</summary>
        public int ActiveColumns => _activeCols;

        /// <summary>One cell's width in DIP (the renderer works in device
        /// pixels; WPF layout wants DIP).</summary>
        public double CellWidthDip => _atlas == null ? 0 : _atlas.CellW / DpiScale;

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

        public void DumpRainPng(string path)
        {
            if (_bmp == null) return;
            try
            {
                var stride = _w * 4;
                var buf = new byte[stride * _h];
                _bmp.CopyPixels(buf, stride, 0);
                var src = BitmapSource.Create(_w, _h, 96, 96, PixelFormats.Pbgra32, null, buf, stride);
                var enc = new PngBitmapEncoder();
                enc.Frames.Add(BitmapFrame.Create(src));
                using var fs = System.IO.File.Create(path);
                enc.Save(fs);
            }
            catch { }
        }
        // ------------------------------------------------------------------
        // Frame
        // ------------------------------------------------------------------

        private void Frame(object sender, EventArgs e)
        {
            if (_bmp == null || _w == 0 || _h == 0) return;

            double now = _clock.Elapsed.TotalSeconds;
            double dt = now - _lastFrameSec;

            // Big surfaces (the full-desktop dock) render at 30 fps — a
            // 2M-pixel fade pass every vsync buys nothing visually.
            int fps = _w * _h > 1_500_000 ? 30 : 60;
            if (dt < 1.0 / fps - 0.0005) return;
            _lastFrameSec = now;
            dt = Math.Clamp(dt, 0.001, 0.25);
            _fpsEma = _fpsEma <= 0 ? 1.0 / dt : _fpsEma * 0.9 + (1.0 / dt) * 0.1;

            ConsumeSnapshot();

            if (!LockSurface(_bmp)) return; // device loss — fresh surfaces, retry next tick
            try
            {
                int stride = _bmp.BackBufferStride;

                // No per-pixel fade pass anymore: decay is managed per cell
                // (wake glyphs at exact log-curve alpha, heads redrawn each
                // frame), so the layer only changes where cells change. A
                // full reset happens only when cell metrics change or a
                // column retires.
                if (_rainClearPending)
                {
                    unsafe { new Span<byte>((void*)_bmp.BackBuffer, _h * stride).Clear(); }
                    foreach (var c in _columns.Values) c.Wake.Clear();
                    _rainClearPending = false;
                }

                if (_cfg.ShowLabels)
                    unsafe { new Span<byte>((void*)_bmp.BackBuffer, _bandH * stride).Clear(); }

                // CINEMA: the movie's body — fade the whole rain layer (the
                // silky trail decay), then keep every column's decorative
                // stream falling. The data columns draw on top after this.
                UpdateActiveColumns();
                if (Cinema)
                {
                    FadeCinema(dt);
                    SyncDecoWall();
                    StepAndDrawDeco(dt, stride);
                }

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
                List<RainColumn> slotless = null;
                foreach (var col in _orderedColumns)
                {
                    if (!_columns.TryGetValue(col.Pid, out var cur) || !cur.Alive) continue;
                    if (idx >= maxSlots)
                    {
                        // beyond the alive cap: no slot this frame
                        slotless ??= new List<RainColumn>();
                        slotless.Add(cur);
                        continue;
                    }
                    int newSlot = busiestAtLeft ? idx : _gridCols - 1 - idx;
                    idx++;

                    if (col.PrevSlot < 0)
                    {
                        // A new id: its column slides OUT from the docked
                        // edge into place instead of popping into existence.
                        col.XOffset = busiestAtLeft
                            ? -(double)(newSlot * _atlas.CellW)
                            : (double)(_w - newSlot * _atlas.CellW);
                    }
                    else if (col.PrevSlot != newSlot)
                    {
                        // Re-ranked: compensate so the rendered position is
                        // continuous, then glide to the new slot.
                        col.XOffset += (col.PrevSlot - newSlot) * (double)_atlas.CellW;
                    }
                    col.PrevSlot = newSlot;
                    col.Slot = newSlot;

                    if (_cfg.ShowLabels) DrawPidLabel(col, stride);
                    StepColumn(col, dt);
                    if (Cinema) RenderColumnCinema(col);
                    else RenderColumn(col);
                }

                // A column that lost its slot (died, or beyond the cap):
                // clear its strip once — in instrument style nothing would
                // decay it, and the label band needs the explicit wipe in
                // either style.
                if (slotless != null)
                    foreach (var col in slotless)
                    {
                        if (col.PrevSlot >= 0)
                        {
                            ClearColumnStrip(col, stride);
                            col.PrevSlot = -1;
                            col.Slot = -1;
                        }
                    }

                _bmp.AddDirtyRect(new Int32Rect(0, 0, _w, _h));
            }
            finally
            {
                UnlockSurface(_bmp);
            }

            if (!Cinema)
            {
                ApplyPendingEtches();
                TickAmbient(dt);
            }
        }

        // ------------------------------------------------------------------
        // Cinema style — the movie look
        // ------------------------------------------------------------------

        /// <summary>The classic trail decay: multiply the rain layer (below
        /// the label band) toward transparent, so every stream leaves the
        /// movie's silky green tail.</summary>
        private unsafe void FadeCinema(double dt)
        {
            int f = (int)Math.Clamp(Math.Pow(0.28, dt) * 256.0, 0, 255);
            int stride = _bmp.BackBufferStride;
            byte* start = (byte*)_bmp.BackBuffer + _bandH * stride;
            long byteCount = (long)(_h - _bandH) * stride;
            if (byteCount <= 0) return;
            byte* end = start + byteCount;
            for (byte* p = start; p < end; p++)
                if (*p != 0) *p = (byte)((*p * f) >> 8);
        }

        /// <summary>The decorative wall of rain: one continuous stream per
        /// grid column, own speed and brightness, restarting at the top
        /// after a breathing gap — green trails, white tips, occasional
        /// mid-trail glyph mutation, exactly the film's texture. Carries no
        /// data; the PID columns fall over it brighter and bloomed.</summary>
        private unsafe void StepAndDrawDeco(double dt, int stride)
        {
            byte* dstBase = (byte*)_bmp.BackBuffer;
            int n = _atlas.GlyphChars.Length;

            for (int c = 0; c < _deco.Length && c < _gridCols; c++)
            {
                var s = _deco[c];
                // the wall lives exactly where the data does: the alive
                // columns hugging the docked edge
                int edge = _cfg.Dock == "left" ? 0 : _gridCols - _deco.Length;
                int x = (edge + c) * _atlas.CellW;
                if (x + _atlas.CellW > _w) break;

                if (s.WaitSec >= 0)
                {
                    s.WaitSec -= dt;
                    if (s.WaitSec < 0)
                    {
                        s.HeadRow = -_rand.NextDouble() * 12;
                        s.Speed = 9 + _rand.NextDouble() * 17;
                        s.Brightness = 0.85 + _rand.NextDouble() * 0.15;
                        s.Glyph = _rand.Next(n);
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

                // green where the head has crossed — each cell is CLEARED
                // first: the previous pass's decayed glyph must not bleed
                // through the new glyph's antialiased pixels (two letters
                // in one cell is overwriting, not rain)
                for (int r = Math.Max(0, prevRow + 1); r <= newRow && r < _gridRows; r++)
                {
                    int cy = _bandH + r * _atlas.CellH;
                    ClearCell(dstBase, stride, x, cy, _atlas.CellW, _atlas.CellH, _w, _h);
                    BlitClipped(dstBase, stride, _atlas.Trail[_rand.Next(n)],
                        _atlas.CellW, _atlas.CellH, x, cy,
                        _w, _h, (int)(256 * s.Brightness));
                }

                // the white tip
                if (newRow >= 0 && newRow < _gridRows)
                {
                    int ty = _bandH + newRow * _atlas.CellH;
                    ClearCell(dstBase, stride, x, ty, _atlas.CellW, _atlas.CellH, _w, _h);
                    BlitClipped(dstBase, stride, _atlas.Head[s.Glyph],
                        _atlas.CellW, _atlas.CellH, x, ty,
                        _w, _h, 244);
                    DebugDraws++;
                }

                // mid-trail mutation — the film's shimmer
                if (newRow > 4 && _rand.NextDouble() < 0.12)
                {
                    int mr = newRow - _rand.Next(1, Math.Min(16, newRow));
                    if (mr >= 0)
                    {
                        int my = _bandH + mr * _atlas.CellH;
                        ClearCell(dstBase, stride, x, my, _atlas.CellW, _atlas.CellH, _w, _h);
                        BlitClipped(dstBase, stride, _atlas.Trail[_rand.Next(n)],
                            _atlas.CellW, _atlas.CellH, x, my,
                            _w, _h, (int)(256 * s.Brightness));
                    }
                }
            }
        }

        /// <summary>Data columns in cinema: the lead redraws every frame —
        /// bloom halo and the bright lifted glyph — and each row it vacates
        /// is stamped bold green (the fade pass turns that into the trail).
        /// No per-cell wake bookkeeping; no backdrop etches.</summary>
        private unsafe void RenderColumnCinema(RainColumn col)
        {
            if (col.Drops.Count == 0) return;
            var (headSet, _) = GlyphSetsFor(col, rx: false);
            byte* dstBase = (byte*)_bmp.BackBuffer;
            int stride = _bmp.BackBufferStride;
            int cw = _atlas.LiftCellW, ch = _atlas.LiftCellH;
            int x = ColumnX(col) + (_atlas.CellW - cw) / 2;
            if (x < 0) return;

            for (int i = col.Drops.Count - 1; i >= 0; i--)
            {
                var d = col.Drops[i];
                if (d.Row < 0 || d.Row >= _gridRows) continue;
                int y = _bandH + d.Row * _atlas.CellH + (_atlas.CellH - ch) / 2;

                if (_atlas.HasBloom)
                {
                    var bloom = d.Rx ? _atlas.RxBloom
                              : col.Blocked ? _atlas.BlockedHeadBloom
                              : _atlas.HeadBloom;
                    int bw = _atlas.BloomCellW, bh = _atlas.BloomCellH;
                    BlitClipped(dstBase, stride, bloom[d.GlyphIndex],
                        bw, bh, x + (cw - bw) / 2, y + (ch - bh) / 2, _w, _h, 256);
                }
                // clear the STANDARD cell before the sharp glyph: the lead
                // must REPLACE the wall glyph under it, not blend with its
                // ghost (clearing the larger lift rect would nick the
                // neighboring cells' glyph edges)
                ClearCell(dstBase, stride, ColumnX(col),
                    _bandH + d.Row * _atlas.CellH, _atlas.CellW, _atlas.CellH, _w, _h);
                BlitClipped(dstBase, stride, headSet[d.GlyphIndex], cw, ch, x, y, _w, _h, 256);
            }
        }

        /// <summary>A vacated data-lead row in cinema: bold green, full
        /// strength — stamped into a CLEARED cell so it replaces the wall
        /// glyph instead of superimposing on it.</summary>
        private unsafe void DrawGreenCell(RainColumn col, int row, int glyphIndex, int alpha)
        {
            if (row < 0 || row >= _gridRows) return;
            int x = ColumnX(col);
            if (x < 0) return;
            byte* dstBase = (byte*)_bmp.BackBuffer;
            int stride = _bmp.BackBufferStride;
            int y = _bandH + row * _atlas.CellH;
            ClearCell(dstBase, stride, x, y, _atlas.CellW, _atlas.CellH, _w, _h);
            BlitClipped(dstBase, stride,
                _atlas.Trail[glyphIndex], _atlas.CellW, _atlas.CellH,
                x, y, _w, _h, alpha);
        }

        /// <summary>Zeroes a cell rect (clipped to the surface) — replacement
        /// semantics for stamps on the ever-occupied cinema wall. Without it
        /// the over-blend keeps a fraction of the previous glyph's
        /// antialiased pixels: two letters in one cell.</summary>
        private static unsafe void ClearCell(byte* dstBase, int stride, int x, int y, int w, int h, int maxW, int maxH)
        {
            int cw = Math.Min(w, maxW - x);
            int ch = Math.Min(h, maxH - y);
            if (cw <= 0 || ch <= 0) return;
            byte* d = dstBase + y * stride + x * 4;
            for (int r = 0; r < ch; r++, d += stride)
                for (int c = 0; c < cw * 4; c++)
                    d[c] = 0;
        }

        /// <summary>Wipes a column's full strip (its last drawn grid cell,
        /// label band included) — for a column that just lost its slot.</summary>
        private unsafe void ClearColumnStrip(RainColumn col, int stride)
        {
            int x = ColumnX(col);
            if (x < 0) return;
            ClearCell((byte*)_bmp.BackBuffer, stride, x, 0, _atlas.CellW, _h, _w, _h);
        }

        /// <summary>Writes this frame's wake into the backdrop: each cell a
        /// lead glyph vacated takes that glyph as a steady ambient
        /// character — from here on it is indistinguishable from the
        /// background field (same color, same size, and it drifts and
        /// mutates with the field like every other backdrop cell).</summary>
        private unsafe void ApplyPendingEtches()
        {
            if (_pendingEtches.Count == 0) return;
            if (_bgBmp == null || _ambientGrid == null) { _pendingEtches.Clear(); return; }

            if (!LockSurface(_bgBmp)) { _pendingEtches.Clear(); return; }
            try
            {
                byte* dstBase = (byte*)_bgBmp.BackBuffer;
                int stride = _bgBmp.BackBufferStride;
                foreach (var (slot, row, glyph) in _pendingEtches)
                {
                    if (slot >= _ambientCols || row >= _ambientRows) continue;
                    _ambientGrid[slot, row] = glyph;
                    int x = slot * _atlas.CellW, y = _bandH + row * _atlas.CellH;
                    ClearCell(dstBase, stride, x, y, _atlas.CellW, _atlas.CellH);
                    BlitClipped(dstBase, stride, _atlas.Ambient[glyph],
                        _atlas.CellW, _atlas.CellH, x, y, _w, _h, 256);
                }
                _bgBmp.AddDirtyRect(new Int32Rect(0, 0, _w, _h));
            }
            finally { UnlockSurface(_bgBmp); }
            _pendingEtches.Clear();
        }

        // ------------------------------------------------------------------
        // Ambient backdrop — the slow, steady-brightness glyph field
        // ------------------------------------------------------------------

        /// <summary>(Re)builds the backdrop grid after a resize or an atlas
        /// rebuild; disabled ambient clears its surface.</summary>
        private void RebuildAmbientGrid()
        {
            if (_bgBmp == null || _atlas == null) return;
            if (Cinema || !_cfg.Ambient)
            {
                // Cinema is pure black behind the rain — the movie has no
                // backdrop field.
                _ambientGrid = null;
                if (!LockSurface(_bgBmp)) return;
                try
                {
                    unsafe { new Span<byte>((void*)_bgBmp.BackBuffer, _h * _bgBmp.BackBufferStride).Clear(); }
                    _bgBmp.AddDirtyRect(new Int32Rect(0, 0, _w, _h));
                }
                finally { UnlockSurface(_bgBmp); }
                return;
            }

            _ambientCols = Math.Max(1, _w / _atlas.CellW);
            _ambientRows = Math.Max(1, (_h - _bandH) / _atlas.CellH);
            _ambientGrid = new int[_ambientCols, _ambientRows];
            for (int c = 0; c < _ambientCols; c++)
                for (int r = 0; r < _ambientRows; r++)
                    _ambientGrid[c, r] = _rand.NextDouble() <= _cfg.AmbientDensity
                        ? _rand.Next(_atlas.GlyphChars.Length) : -1;
            RedrawAmbientFull();
        }

        private unsafe void RedrawAmbientFull()
        {
            if (_bgBmp == null) return;
            if (!LockSurface(_bgBmp)) return;
            try
            {
                new Span<byte>((void*)_bgBmp.BackBuffer, _h * _bgBmp.BackBufferStride).Clear();
                if (_ambientGrid != null)
                {
                    byte* dstBase = (byte*)_bgBmp.BackBuffer;
                    int stride = _bgBmp.BackBufferStride;
                    for (int c = 0; c < _ambientCols; c++)
                        for (int r = 0; r < _ambientRows; r++)
                            BlitAmbientCell(dstBase, stride, c, r);
                }
                _bgBmp.AddDirtyRect(new Int32Rect(0, 0, _w, _h));
            }
            finally { UnlockSurface(_bgBmp); }
        }

        private unsafe void BlitAmbientCell(byte* dstBase, int stride, int c, int r)
        {
            int idx = _ambientGrid[c, r];
            if (idx < 0) return;
            BlitClipped(dstBase, stride, _atlas.Ambient[idx], _atlas.CellW, _atlas.CellH,
                c * _atlas.CellW, _bandH + r * _atlas.CellH, _w, _h, 256);
        }

        /// <summary>The backdrop's life — which is to say, almost none: by
        /// default it is FROZEN (ambientDriftSeconds 0). A background that
        /// randomly changes under the rain breaks the illusion; the only
        /// backdrop changes are real ones — falling wakes etching their
        /// characters in. Opt-in drift eases the whole field down one row
        /// at a time.</summary>
        private void TickAmbient(double dt)
        {
            if (!_cfg.Ambient || _bgBmp == null || _ambientGrid == null) return;
            if (_cfg.AmbientDriftSeconds <= 0) return;

            _driftAccumSec += dt;
            if (_driftAccumSec < _cfg.AmbientDriftSeconds) return;
            _driftAccumSec = 0;

            for (int c = 0; c < _ambientCols; c++)
            {
                for (int r = _ambientRows - 1; r > 0; r--)
                    _ambientGrid[c, r] = _ambientGrid[c, r - 1];
                _ambientGrid[c, 0] = _rand.NextDouble() <= _cfg.AmbientDensity
                    ? _rand.Next(_atlas.GlyphChars.Length) : -1;
            }
            RedrawAmbientFull();
        }

        private unsafe void ClearCell(byte* dstBase, int stride, int x, int y, int w, int h)
        {
            // Bounds-guarded: sliding columns can hand us rects that poke
            // past the surface, and a negative write would corrupt memory.
            if (x < 0 || y < 0 || w <= 0 || h <= 0 || x + w > _w || y + h > _h) return;
            for (int r = 0; r < h; r++)
                new Span<byte>(dstBase + (y + r) * stride + x * 4, w * 4).Clear();
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

        /// <summary>The PID reads vertically down its column — a rain column
        /// is one glyph wide, so sideways labels would spill into the
        /// neighbor's rain. Hover (when not click-through) shows the full
        /// story: name, counters, block state.</summary>
        private unsafe void DrawPidLabel(RainColumn col, int stride)
        {
            int x = ColumnX(col) + Math.Max(0, (_atlas.CellW - _atlas.LabelCellW) / 2);
            if (x < 0) return;

            string digits = col.Pid.ToString();
            if (digits.Length > PidLabelRows) digits = digits.Substring(digits.Length - PidLabelRows);

            byte* dstBase = (byte*)_bmp.BackBuffer;
            var font = col.Blocked ? _atlas.LabelDigitsBlocked : _atlas.LabelDigits;
            for (int i = 0; i < digits.Length; i++)
            {
                int y = 3 + i * _atlas.LabelCellH;
                BlitClipped(dstBase, stride, font[digits[i] - '0'],
                    _atlas.LabelCellW, _atlas.LabelCellH, x, y, _w, _h, 256);
            }
        }

        private void StepColumn(RainColumn col, double dt)
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
                StepDrops(col, capTx, rx: false);

                if (_cfg.RxMode)
                {
                    col.FallCarryRx += dt * _cfg.FallRowsPerSecond * 0.5;
                    int capRx = (int)col.FallCarryRx;
                    col.FallCarryRx -= capRx;
                    StepDrops(col, capRx, rx: true);
                }
            }
        }

        private void StepDrops(RainColumn col, int maxAdvance, bool rx)
        {
            double budget = Math.Min(rx ? col.RxBudget : col.Budget, 600);
            int glyphCount = _atlas.GlyphChars.Length;
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
                            // bold green where the lead passed — the fade
                            // pass shapes it into the movie's trail
                            DrawGreenCell(col, lead.Row, lead.GlyphIndex, 256);
                        }
                        else
                        {
                            // The vacated character begins its logarithmic
                            // fade — drawn over the identical backdrop glyph
                            // etched beneath it, so the completed fade
                            // resolves into a background character.
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
                        // Instrument keeps exact per-cell clearing (no fade
                        // pass there); cinema's fade eats the residue.
                        if (!Cinema) ClearHeadRect(ColumnX(col), lead.Row - 1);
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

        private (byte[][] head, byte[][] trail) GlyphSetsFor(RainColumn col, bool rx)
        {
            if (rx) return (_atlas.RxLift, _atlas.RxLift);
            return col.Blocked
                ? (_atlas.BlockedHeadLift, _atlas.BlockedLift)
                : (_atlas.HeadLift, _atlas.TrailLift);
        }

        // ------------------------------------------------------------------
        // Per-column rendering: log-fading wake, bloomed lead
        // ------------------------------------------------------------------

        /// <summary>Incremental dimming by TRAIL DISTANCE — the character
        /// right behind the lead is ~full lead brightness (same color
        /// family, capped a hair under so the lead stays strictly
        /// brightest), each further character one log-step dimmer, gone at
        /// the trail length. No time decay: idle streams freeze in place
        /// and animate only when events move them.</summary>
        private double WakeAlphaByDistance(int dist)
        {
            double d = _wakeCharLength;
            if (dist < 0) dist = 0;
            if (dist >= d) return 0;
            double f = Math.Log(1 + _wakeCurveK * (d - dist)) * WakeDenom;
            return Math.Clamp(f, 0, 1) * (248.0 / 256.0);
        }

        /// <summary>The column's pixel x this frame: its slot plus any
        /// slide offset still easing toward rest.</summary>
        private int ColumnX(RainColumn col) =>
            col.Slot * _atlas.CellW + (int)Math.Round(col.XOffset);

        private unsafe void RenderColumn(RainColumn col)
        {
            byte* dstBase = (byte*)_bmp.BackBuffer;
            int stride = _bmp.BackBufferStride;

            int xNow = ColumnX(col);
            int xPrev = col.LastDrawnX == double.MinValue ? xNow : (int)col.LastDrawnX;
            bool moved = xNow != xPrev;

            // The lead row of each color anchors its wake's distances; with
            // no lead (idle stream) the staircase freezes where it was.
            int leadTx = -1, leadRx = -1;
            for (int i = 0; i < col.Drops.Count; i++)
            {
                var d = col.Drops[i];
                if (d.Row < 0) continue;
                if (d.Rx) { if (d.Row > leadRx) leadRx = d.Row; }
                else { if (d.Row > leadTx) leadTx = d.Row; }
            }

            // The wake: characters behind the lead — same brightness family
            // as the lead, dimmer incrementally by distance — drawn over the
            // identical (dim) backdrop glyph etched beneath. While the
            // column glides, its previous position is cleared too.
            for (int i = col.Wake.Count - 1; i >= 0; i--)
            {
                var w = col.Wake[i];
                int y = _bandH + w.Row * _atlas.CellH;

                int anchor = w.Rx ? leadRx : leadTx;
                if (anchor >= 0)
                {
                    int dist = anchor - w.Row;
                    if (dist > _wakeCharLength || w.Row < 0 || w.Row >= _gridRows)
                    {
                        if (moved)
                            ClearCell(dstBase, stride, xPrev, y, _atlas.CellW, _atlas.CellH);
                        ClearCell(dstBase, stride, xNow, y, _atlas.CellW, _atlas.CellH);
                        col.Wake.RemoveAt(i);
                        continue;
                    }
                    w.Alpha = WakeAlphaByDistance(dist);
                }

                var set = w.Rx ? _atlas.Rx : col.Blocked ? _atlas.BlockedHead : _atlas.Head;
                if (moved)
                    ClearCell(dstBase, stride, xPrev, y, _atlas.CellW, _atlas.CellH);
                ClearCell(dstBase, stride, xNow, y, _atlas.CellW, _atlas.CellH);
                if (xNow >= 0 && xNow + _atlas.CellW <= _w && w.Alpha > 0.004)
                    BlitClipped(dstBase, stride, set[w.Glyph], _atlas.CellW, _atlas.CellH,
                        xNow, y, _w, _h, (int)(256 * w.Alpha));
            }

            // The lead(s): shadow, soft bloom, the single brightest glyph —
            // redrawn every frame, with last frame's bounds cleared.
            for (int i = col.Drops.Count - 1; i >= 0; i--)
                RenderHead(col, col.Drops[i], xNow, xPrev);

            col.LastDrawnX = xNow;
        }

        /// <summary>The rectangle a lead occupies: its glyph cell inflated
        /// to cover the bloom halo and the shadow's offset, at a given
        /// column pixel base. Clearing exactly this removes everything the
        /// head drew — with no fade pass, precision is what prevents
        /// residue.</summary>
        private (int x, int y, int w, int h) HeadRect(int xBase, int row)
        {
            int cw = _atlas.LiftCellW, ch = _atlas.LiftCellH;
            int x = xBase + (_atlas.CellW - cw) / 2;
            int y = _bandH + row * _atlas.CellH + (_atlas.CellH - ch) / 2;
            int bw = _atlas.HasBloom ? _atlas.BloomCellW : cw;
            int bh = _atlas.HasBloom ? _atlas.BloomCellH : ch;
            int so = _atlas.HasLift ? Math.Max(1, (cw - _atlas.CellW) / 2) : 0;
            return (Math.Min(x, x + (cw - bw) / 2),
                    Math.Min(y, y + (ch - bh) / 2),
                    Math.Max(cw, bw) + so,
                    Math.Max(ch, bh) + so + 1);
        }

        private unsafe void ClearHeadRect(int xBase, int row)
        {
            var (x, y, w, h) = HeadRect(xBase, row);
            int cx = Math.Max(0, x), cy = Math.Max(0, y);
            int cw = Math.Min(w, _w - cx), ch = Math.Min(h, _h - cy);
            if (cw <= 0 || ch <= 0) return;
            ClearCell((byte*)_bmp.BackBuffer, _bmp.BackBufferStride, cx, cy, cw, ch);
        }

        private unsafe void RenderHead(RainColumn col, RainDrop drop, int xNow, int xPrev)
        {
            if (drop.Row < 0 || drop.Row >= _gridRows) { drop.LastRow = drop.Row; return; }
            var (headSet, _) = GlyphSetsFor(col, drop.Rx);

            // Clear everything the head drew last frame (previous row and
            // or previous column position), then its current bounds.
            if (drop.LastRow >= 0 && (drop.LastRow != drop.Row || xPrev != xNow))
                ClearHeadRect(xPrev, drop.LastRow);
            ClearHeadRect(xNow, drop.Row);
            drop.LastRow = drop.Row;

            // Sliding in from off-pane: stay clear of the surface edge.
            if (xNow < 0) return;

            byte* dstBase = (byte*)_bmp.BackBuffer;
            int stride = _bmp.BackBufferStride;
            int cw = _atlas.LiftCellW, ch = _atlas.LiftCellH;
            int x = xNow + (_atlas.CellW - cw) / 2;
            int y = _bandH + drop.Row * _atlas.CellH + (_atlas.CellH - ch) / 2;
            int so = _atlas.HasLift ? Math.Max(1, (cw - _atlas.CellW) / 2) : 0;

            // depth first, glow second, the crisp glyph on top
            if (_atlas.HasLift)
                BlitClipped(dstBase, stride, _atlas.ShadowLift[drop.GlyphIndex],
                    cw, ch, x + so, y + so + 1, _w, _h, 256);

            if (_atlas.HasBloom)
            {
                var bloom = drop.Rx ? _atlas.RxBloom
                          : col.Blocked ? _atlas.BlockedHeadBloom
                          : _atlas.HeadBloom;
                int bw = _atlas.BloomCellW, bh = _atlas.BloomCellH;
                BlitClipped(dstBase, stride, bloom[drop.GlyphIndex],
                    bw, bh, x + (cw - bw) / 2, y + (ch - bh) / 2, _w, _h, 256);
            }

            BlitClipped(dstBase, stride, headSet[drop.GlyphIndex], cw, ch, x, y, _w, _h, 256);
        }

        /// <summary>Source-over blend of a premultiplied glyph cell onto the
        /// surface (both Pbgra32, channel order identical). copyW/copyH may
        /// be smaller than the source cell for edge clipping; srcW keeps the
        /// source rows aligned through the clipped columns; alphaScale
        /// (0..256) scales the glyph's alpha — the wake's log curve rides
        /// on this instead of pre-baked fade levels.</summary>
        private static unsafe void Blit(byte* dstBase, int stride, byte[] src, int srcW, int copyW, int copyH, int x, int y, int alphaScale)
        {
            byte* dst = dstBase + y * stride + x * 4;
            int si = 0;
            for (int r = 0; r < copyH; r++, dst += stride)
            {
                byte* d = dst;
                for (int c = 0; c < copyW; c++, d += 4, si += 4)
                {
                    int sa = (src[si + 3] * alphaScale) >> 8;
                    if (sa == 0) continue;
                    if (sa == 255)
                    {
                        d[0] = src[si]; d[1] = src[si + 1]; d[2] = src[si + 2]; d[3] = 255;
                        continue;
                    }
                    int inv = 255 - sa;
                    d[0] = (byte)(src[si] + ((d[0] * inv) >> 8));
                    d[1] = (byte)(src[si + 1] + ((d[1] * inv) >> 8));
                    d[2] = (byte)(src[si + 2] + ((d[2] * inv) >> 8));
                    d[3] = (byte)(sa + ((d[3] * inv) >> 8));
                }
                si += (srcW - copyW) * 4;
            }
        }

        /// <summary>Blit with right/bottom clipping against the surface.</summary>
        private static unsafe void BlitClipped(byte* dstBase, int stride, byte[] src, int srcW, int srcH, int x, int y, int maxW, int maxH, int alphaScale)
        {
            int w = Math.Min(srcW, maxW - x);
            int h = Math.Min(srcH, maxH - y);
            if (w <= 0 || h <= 0) return;
            Blit(dstBase, stride, src, srcW, w, h, x, y, alphaScale);
        }

        // ------------------------------------------------------------------
        // Hover
        // ------------------------------------------------------------------

        /// <summary>Human story of the column under a DIP x — the window
        /// turns it into a tooltip when the overlay takes mouse input.</summary>
        public string DescribeColumnAt(double dipX)
        {
            if (_atlas == null) return null;
            int slot = (int)((dipX * DpiScale) / _atlas.CellW);
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
