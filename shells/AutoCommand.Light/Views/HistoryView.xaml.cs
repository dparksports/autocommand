using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace AutoCommand.Light.Views
{
    /// <summary>
    /// The readable history: Light's own event ledger rendered through the
    /// shared AuditTrail transform — the same plain-language composer the
    /// Advanced app's Audit page uses. Read-only by contract; the ledger
    /// file itself is plain text under Light's data folder.
    /// </summary>
    public partial class HistoryView : UserControl
    {
        private readonly List<IncidentVm> _items = new();

        public HistoryView()
        {
            InitializeComponent();
            IncidentList.ItemsSource = _items;
            Loaded += (s, e) => Refresh();
        }

        public void Refresh()
        {
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
                    Sentence = "Nothing has happened yet. Blocks, pauses and the panic button all appear here, in plain words.",
                });

            IncidentList.Items.Refresh();
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => Refresh();

        public sealed class IncidentVm
        {
            public string When { get; set; }
            public string Sentence { get; set; }
        }
    }
}
