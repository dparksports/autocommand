using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace AutoCommand.Light.Controls
{
    /// <summary>Three-way segmented selector. Options are plain strings;
    /// Value is the selected one; flipping raises ValueChanged — the app
    /// page maps that straight onto the permission and the firewall.</summary>
    public partial class Segmented : UserControl
    {
        public static readonly DependencyProperty OptionsProperty = DependencyProperty.Register(
            nameof(Options), typeof(string[]), typeof(Segmented),
            new PropertyMetadata(Array.Empty<string>(), OnOptionsChanged));

        public static readonly DependencyProperty ValueProperty = DependencyProperty.Register(
            nameof(Value), typeof(string), typeof(Segmented),
            new PropertyMetadata("", OnValueChanged));

        public string[] Options
        {
            get => (string[])GetValue(OptionsProperty);
            set => SetValue(OptionsProperty, value);
        }

        public string Value
        {
            get => (string)GetValue(ValueProperty);
            set => SetValue(ValueProperty, value);
        }

        public event EventHandler? ValueChanged;
        public bool SuppressCallbacks { get; set; }

        public Segmented()
        {
            InitializeComponent();
        }

        private static void OnOptionsChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            var c = (Segmented)d;
            var opts = c.Options ?? Array.Empty<string>();
            var radios = new[] { c.Opt0, c.Opt1, c.Opt2 };
            for (var i = 0; i < radios.Length; i++)
            {
                radios[i].Content = i < opts.Length ? opts[i] : "";
                radios[i].Visibility = i < opts.Length ? Visibility.Visible : Visibility.Collapsed;
            }
            c.SyncSelection();
        }

        private static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            var c = (Segmented)d;
            if (!c.SuppressCallbacks) c.SyncSelection();
        }

        private void SyncSelection()
        {
            var opts = Options ?? Array.Empty<string>();
            var idx = Array.IndexOf(opts, Value);
            var radios = new[] { Opt0, Opt1, Opt2 };
            SuppressCallbacks = true;
            for (var i = 0; i < radios.Length; i++) radios[i].IsChecked = i == idx;
            SuppressCallbacks = false;
        }

        private void Opt_Checked(object sender, RoutedEventArgs e)
        {
            if (SuppressCallbacks) return;
            var idx = int.Parse(((RadioButton)sender).Tag?.ToString() ?? "0");
            var opts = Options ?? Array.Empty<string>();
            if (idx < opts.Length)
            {
                Value = opts[idx];
                ValueChanged?.Invoke(this, EventArgs.Empty);
            }
        }
    }
}
