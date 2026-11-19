using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace AutoCommand.Light.Views
{
    /// <summary>
    /// The record: today's held attempts (who, where, when — the gate's
    /// rings) above the shared AuditTrail sentences (everything the app
    /// itself did). Read-only by contract; the ledger file is plain text
    /// under Light's data folder.
    /// </summary>
    public partial class AttemptsView : UserControl
    {
        private readonly List<IncidentVm> _items = new();

        public AttemptsView()
        {
            InitializeComponent();
            IncidentList.ItemsSource = _items;
            Loaded += (s, e) => Refresh();
        }

        public void Refresh()
        {
            // ── today's held attempts ───────────────────────────────────
            AttemptsList.Children.Clear();
            var attempts = LightGate.AttemptsToday()
                .OrderByDescending(a => a.TimeUtc).Take(40).ToList();
            AttemptsEmpty.Visibility = attempts.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            foreach (var a in attempts)
            {
                var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
                row.Children.Add(new TextBlock
                {
                    Text = a.TimeUtc.ToLocalTime().ToString("HH:mm"),
                    FontSize = 12,
                    Foreground = (System.Windows.Media.Brush)FindResource("MutedTextBrush"),
                    Width = 46,
                    VerticalAlignment = VerticalAlignment.Center,
                });
                row.Children.Add(new TextBlock
                {
                    Text = a.AppDisplayName,
                    FontWeight = FontWeights.SemiBold,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(0, 0, 10, 0),
                });
                row.Children.Add(new TextBlock
                {
                    Text = string.IsNullOrWhiteSpace(a.Destination) ? "" : "→ " + a.Destination,
                    FontSize = 12,
                    Foreground = (System.Windows.Media.Brush)FindResource("TextSecondaryBrush"),
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    VerticalAlignment = VerticalAlignment.Center,
                });
                AttemptsList.Children.Add(row);
            }

            // ── the app's own history, in sentences ─────────────────────
            _items.Clear();
            try
            {
                var events = AuditTrail.ReadEvents(LightServices.Ledger.EventLogPath);
                var incidents = AuditTrail.BuildIncidents(events);
                // newest first — BuildIncidents returns them oldest-first,
                // and List<T>.Reverse() is the void in-place sort, not LINQ
                for (var i = incidents.Count - 1; i >= 0; i--)
                {
                    var incident = incidents[i];
                    _items.Add(new IncidentVm
                    {
                        When = incident.StartUtc.ToLocalTime().ToString("MMM d, HH:mm"),
                        Sentence = string.IsNullOrEmpty(incident.DayHeader)
                            ? incident.Sentence
                            : $"{incident.DayHeader} — {incident.Sentence}",
                    });
                }
            }
            catch { // an unreadable ledger shows the empty state, never a crash
            }

            if (_items.Count == 0)
                _items.Add(new IncidentVm
                {
                    When = "",
                    Sentence = "Nothing yet. Opens, answers and the panic button all appear here, in plain words.",
                });

            IncidentList.Items.Refresh();
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => Refresh();

        public sealed class IncidentVm
        {
            public string When { get; set; } = "";
            public string Sentence { get; set; } = "";
        }
    }
}
