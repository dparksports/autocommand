using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using FontFamily = System.Windows.Media.FontFamily;
using Point = System.Windows.Point;

namespace AutoCommand.Matrix
{
    /// <summary>One resolved glyph: the face that owns it, its index there,
    /// and its advance at the case's em. Faces resolve once per config — a
    /// missing character falls back down the chain, so Consolas can carry a
    /// katakana alphabet through a CJK face without the rain ever noticing.
    /// The solo lists are the ready-made single-glyph arguments the draw
    /// path reuses for every cell.</summary>
    internal sealed class GlyphFace
    {
        public readonly GlyphTypeface Type;
        public readonly ushort Glyph;
        public readonly double Advance;
        public readonly List<ushort> SoloIndices;
        public readonly List<char> SoloChars;

        public GlyphFace(GlyphTypeface type, ushort glyph, double advance, char ch)
        {
            Type = type;
            Glyph = glyph;
            Advance = advance;
            SoloIndices = new List<ushort> { glyph };
            SoloChars = new List<char> { ch };
        }
    }

    /// <summary>
    /// The rain's type case, text edition: the configured font (an installed
    /// family, or the user's own .ttf/.otf — a matrix code font drops
    /// straight in) resolved once into per-character glyphs with a fallback
    /// chain, plus one frozen brush per color role. A frame of rain is
    /// nothing but GlyphRun drawing: WPF owns the rasterization, the glyph
    /// caches and every GPU resource, so there is no atlas, no lock
    /// protocol, and nothing a render-device loss can tear down under the
    /// frame loop (the crash class the bitmap engine could not fully
    /// defend — see crash.log 2026-11-08/09/11).
    ///
    /// Monospace fonts (Consolas, Cascadia Mono…) look the most Matrix;
    /// proportional fonts work, each glyph centered in its cell.
    /// </summary>
    public sealed class GlyphCase
    {
        public string ResolvedFont;          // what actually loaded, for the balloon
        public string GlyphChars;

        /// <summary>Rain glyph cell, DIPs.</summary>
        public double CellW, CellH;
        /// <summary>PID-label cell (smaller), DIPs.</summary>
        public double LabelCellW, LabelCellH;
        /// <summary>Em sizes: grid glyphs, PID labels, and the zLift-scaled
        /// falling lead (1.0 = flat, same size as the grid).</summary>
        public double Em, LabelEm, LiftEm;
        public bool HasLift;

        public Brush Trail, Head, Blocked, BlockedHead, Rx, Ambient;
        public Brush Label, LabelBlocked;
        /// <summary>Translucent black — the offset shadow that sells the
        /// zLift elevation. Null when flat.</summary>
        public Brush Shadow;
        /// <summary>Radial halos for the lead glyph, per role. Null when
        /// bloom is off.</summary>
        public Brush HeadBloom, BlockedHeadBloom, RxBloom;

        internal GlyphFace[] Faces;          // per charset index
        internal GlyphFace[] Digits = new GlyphFace[10];

        private readonly List<GlyphTypeface> _fallbacks = new();
        private GlyphTypeface _primary;
        // Lazily-resolved label glyphs for the process names drawn vertically
        // in the label band — any character the font chain can render, not
        // just the rain charset. UI-thread only (the frame loop), so no lock.
        private readonly Dictionary<char, GlyphFace> _labelChars = new();

        /// <summary>Resolve (and cache) one character at the label em size
        /// for the vertical name labels.</summary>
        internal GlyphFace LabelChar(char ch)
        {
            if (_labelChars.TryGetValue(ch, out var f)) return f;
            f = Resolve(_primary, ch, LabelEm);
            _labelChars[ch] = f;
            return f;
        }

        // ------------------------------------------------------------------

        public static GlyphCase Build(MatrixRainConfig cfg)
        {
            var c = new GlyphCase();
            var primary = ResolvePrimary(cfg, c._fallbacks, out c.ResolvedFont);
            c._primary = primary;
            string chars = CharsetFor(cfg.Charset);
            c.GlyphChars = chars;

            c.Em = cfg.FontSizePx;
            c.LabelEm = Math.Max(7.0, cfg.FontSizePx * 0.62);

            // Cell metrics from the widest glyph in the chosen set — the
            // movie's tight vertical stack.
            double maxW = 1;
            c.Faces = new GlyphFace[chars.Length];
            for (int i = 0; i < chars.Length; i++)
            {
                c.Faces[i] = c.Resolve(primary, chars[i], c.Em);
                maxW = Math.Max(maxW, c.Faces[i].Advance);
            }
            c.CellW = Math.Max(4, Math.Ceiling(maxW) + 2);
            c.CellH = Math.Max(6, Math.Ceiling(c.Em * 1.12));

            var zero = c.Resolve(primary, '0', c.LabelEm);
            for (int d = 0; d < 10; d++)
                c.Digits[d] = c.Resolve(primary, (char)('0' + d), c.LabelEm);
            c.LabelCellW = Math.Max(4, Math.Ceiling(zero.Advance) + 2);
            c.LabelCellH = Math.Max(5, Math.Ceiling(c.LabelEm * 1.45));

            double lift = Math.Clamp(cfg.ZLift, 1.0, 1.6);
            c.HasLift = lift > 1.001;
            c.LiftEm = c.Em * lift;

            var col = cfg.Colors;
            c.Trail = Solid(col.Trail);
            c.Head = Solid(col.Head);
            c.Blocked = Solid(col.Blocked);
            c.BlockedHead = Solid(col.BlockedHead);
            c.Rx = Solid(col.Rx);
            c.Ambient = Solid(col.Ambient);
            c.Label = Solid(col.Label);
            c.LabelBlocked = Solid(col.Blocked);
            c.Shadow = c.HasLift ? Solid("#000000", 90) : null;
            c.HeadBloom = cfg.Bloom ? Halo(col.Head) : null;
            c.BlockedHeadBloom = cfg.Bloom ? Halo(col.BlockedHead) : null;
            c.RxBloom = cfg.Bloom ? Halo(col.Rx) : null;

            return c;
        }

        private GlyphFace Resolve(GlyphTypeface primary, char ch, double em)
        {
            if (primary.CharacterToGlyphMap.TryGetValue(ch, out var g))
                return new GlyphFace(primary, g, primary.AdvanceWidths[g] * em, ch);
            foreach (var f in _fallbacks)
                if (f.CharacterToGlyphMap.TryGetValue(ch, out g))
                    return new GlyphFace(f, g, f.AdvanceWidths[g] * em, ch);
            // Not in any face — fall back to the primary's replacement glyph
            // rather than dropping the character (the show must rain).
            if (!primary.CharacterToGlyphMap.TryGetValue('?', out g))
                g = 0;
            return new GlyphFace(primary, g, primary.AdvanceWidths[g] * em, ch);
        }

        /// <summary>
        /// Font resolution order: the configured font file (its internal
        /// family name read straight out of the file, so users never have
        /// to guess it), then the configured installed family, then
        /// Consolas — the rain always has a face. The fallback chain behind
        /// it covers characters the primary face lacks (katakana in
        /// Consolas, say).
        /// </summary>
        private static GlyphTypeface ResolvePrimary(MatrixRainConfig cfg, List<GlyphTypeface> fallbacks, out string resolved)
        {
            if (!string.IsNullOrWhiteSpace(cfg.FontFile) && File.Exists(cfg.FontFile))
            {
                try
                {
                    var fileUri = new Uri("file:///" + Path.GetFullPath(cfg.FontFile).Replace('\\', '/'));
                    var gt = new GlyphTypeface(fileUri);
                    string name = null;
                    if (gt.FamilyNames != null)
                    {
                        if (!gt.FamilyNames.TryGetValue(CultureInfo.GetCultureInfo("en-us"), out name))
                            name = gt.FamilyNames.Values.FirstOrDefault();
                    }
                    name ??= Path.GetFileNameWithoutExtension(cfg.FontFile);
                    resolved = $"{name} ({Path.GetFileName(cfg.FontFile)})";
                    AddFallbacks(fallbacks, "Yu Gothic UI", "Meiryo", "MS Gothic", "Segoe UI");
                    return gt;
                }
                catch { /* unreadable font file — fall through to installed */ }
            }

            var family = new FontFamily(cfg.FontFamily);
            if (TryFace(family, out var face))
            {
                resolved = family.Source + " (installed)";
                AddFallbacks(fallbacks, "Yu Gothic UI", "Meiryo", "MS Gothic", "Segoe UI");
                return face;
            }

            family = new FontFamily("Consolas");
            resolved = $"Consolas (fallback — '{cfg.FontFamily}' not installed)";
            AddFallbacks(fallbacks, "Yu Gothic UI", "Meiryo", "MS Gothic", "Segoe UI");
            if (TryFace(family, out face)) return face;
            var last = new Typeface(SystemFonts.MessageFontFamily, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
            return last.TryGetGlyphTypeface(out face)
                ? face
                : throw new InvalidOperationException("no usable font face on this system");
        }

        private static bool TryFace(FontFamily family, out GlyphTypeface face)
        {
            var tf = new Typeface(family, FontStyles.Normal, FontWeights.Bold, FontStretches.Normal);
            return tf.TryGetGlyphTypeface(out face);
        }

        private static void AddFallbacks(List<GlyphTypeface> fallbacks, params string[] families)
        {
            foreach (var name in families)
                if (TryFace(new FontFamily(name), out var f))
                    fallbacks.Add(f);
        }

        private static Brush Solid(string hex, byte alpha = 255)
        {
            var opaque = (Color)ColorConverter.ConvertFromString(hex);
            var c = alpha >= 255 ? opaque : Color.FromArgb(alpha, opaque.R, opaque.G, opaque.B);
            var b = new SolidColorBrush(c);
            b.Freeze();
            return b;
        }

        /// <summary>Soft glow halo for the lead glyph: a radial gradient of
        /// the role color fading to nothing — no bitmap blur, no cached
        /// halo cells; the GPU shades the ellipse where it stands.</summary>
        private static Brush Halo(string hex)
        {
            var c = (Color)ColorConverter.ConvertFromString(hex);
            var g = new RadialGradientBrush
            {
                GradientStops =
                {
                    new GradientStop(Color.FromArgb(150, c.R, c.G, c.B), 0.0),
                    new GradientStop(Color.FromArgb(55,  c.R, c.G, c.B), 0.45),
                    new GradientStop(Color.FromArgb(0,   c.R, c.G, c.B), 1.0)
                }
            };
            g.Freeze();
            return g;
        }

        /// <summary>The falling alphabet. The default is katakana plus a
        /// few machine symbols — no roman letters, no digits: the field
        /// should read as something not made for human eyes. Named sets or
        /// a literal string of characters (≥4, no spaces) for a custom
        /// alphabet.</summary>
        internal static string CharsetFor(string spec)
        {
            const string latin = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            const string digits = "0123456789";
            const string symbols = "*+-/<>=|";
            // Half-width katakana — the movie's glyph set.
            string katakana = new string(Enumerable.Range(0xFF66, 0xFF9D - 0xFF66 + 1).Select(i => (char)i).ToArray());

            switch ((spec ?? "").Trim().ToLowerInvariant())
            {
                case "katakana-latin": return Dedupe(katakana + latin + digits + symbols);
                case "latin": return Dedupe(latin + digits + symbols);
                case "digits": return digits;
                case "":
                case "katakana":
                default:
                    string trimmed = (spec ?? "").Trim();
                    // A literal alphabet — but never one of the NAMED sets:
                    // "katakana" reaching here used to resolve to the four
                    // letters k-a-t-n (inherited from the bitmap atlas).
                    string lower = trimmed.ToLowerInvariant();
                    if (trimmed.Length >= 4 && !trimmed.Contains(' ') &&
                        lower != "katakana-latin" && lower != "latin" &&
                        lower != "digits" && lower != "katakana")
                        return Dedupe(trimmed);
                    return Dedupe(katakana + symbols);   // the alien default
            }
        }

        private static string Dedupe(string s)
        {
            var seen = new HashSet<char>();
            var sb = new System.Text.StringBuilder(s.Length);
            foreach (var ch in s)
                if (seen.Add(ch)) sb.Append(ch);
            return sb.ToString();
        }
    }

    /// <summary>
    /// Collects glyph cells and draws each as a single-glyph GlyphRun
    /// positioned by its baseline ORIGIN. (Multi-glyph runs with
    /// per-glyph offsets render nothing on this WPF — offsets are not
    /// absolute positions; origin is the only reliable placement — so one
    /// run per cell it is. The glyph lists are cached per face; the run
    /// object itself is the only per-cell allocation.)
    /// </summary>
    internal sealed class GlyphBatch
    {
        private readonly double _em;
        private readonly double _ppd;
        private readonly List<Cell> _cells = new();

        private readonly struct Cell
        {
            public readonly GlyphFace Face;
            public readonly double X, Baseline;
            public Cell(GlyphFace f, double x, double b) { Face = f; X = x; Baseline = b; }
        }

        public GlyphBatch(double em, double pixelsPerDip)
        {
            _em = em;
            _ppd = pixelsPerDip;
        }

        public int Count => _cells.Count;

        public void Add(GlyphFace face, double x, double baselineY) =>
            _cells.Add(new Cell(face, x, baselineY));

        public void Flush(DrawingContext dc, Brush brush)
        {
            // (face, bidi, sideways, renderingEmSize, pixelsPerDip, indices,
            //  origin, advances, offsets, characters, deviceFont, clusterMap,
            //  caretStops, language). Mind the order: em is the DOUBLE,
            //  pixelsPerDip the FLOAT — swapping them renders every glyph at
            //  one DIP, invisibly.
            foreach (var c in _cells)
                dc.DrawGlyphRun(brush, new GlyphRun(c.Face.Type, 0, false, _em, (float)_ppd,
                    c.Face.SoloIndices, new Point(c.X, c.Baseline), ZeroAdvance,
                    null, c.Face.SoloChars, null, null, null, null));
            _cells.Clear();
        }

        private static readonly List<double> ZeroAdvance = new() { 0 };
    }
}
