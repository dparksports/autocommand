using System;
using System.IO;
using System.Windows;

namespace AutoCommand.Light
{
    /// <summary>
    /// The theme switch: two palettes (dark is the default), one merged
    /// dictionary slot, and a plain file for the choice — Light's "plain
    /// inspectable state" rule applies to preferences too, so the choice
    /// is theme.txt in Light's data folder, not the registry.
    ///
    /// The swap replaces MergedDictionaries[0], which is the palette by
    /// construction (App.xaml merges exactly one dictionary). Every brush
    /// consumer is a DynamicResource, so the repaint is in-place and
    /// live; Changed lets code-composed surfaces (Today's histogram, the
    /// Apps rows' chip brushes) rebuild against the new palette.
    /// </summary>
    public static class LightTheme
    {
        public const string Dark = "dark";
        public const string Light = "light";

        private static string _current = Dark;
        public static string Current => _current;

        public static event Action? Changed;

        private static string Path => System.IO.Path.Combine(LightServices.Root, "theme.txt");

        public static void Initialize() => Apply(ReadSaved());

        /// <summary>Missing or unreadable file = dark, the default the
        /// product first-run-teaches.</summary>
        public static string ReadSaved()
        {
            try
            {
                var saved = File.ReadAllText(Path).Trim();
                return saved == Light ? Light : Dark;
            }
            catch { return Dark; }
        }

        public static void Apply(string theme)
        {
            _current = theme == Light ? Light : Dark;
            var source = _current == Light
                ? new Uri("Themes/Palette.Light.xaml", UriKind.Relative)
                : new Uri("Themes/Palette.Dark.xaml", UriKind.Relative);
            var merged = Application.Current.Resources.MergedDictionaries;
            merged[0] = new ResourceDictionary { Source = source };
            try { File.WriteAllText(Path, _current); }
            catch { // a read-only profile keeps the choice for the session
            }
            Changed?.Invoke();
        }
    }
}
