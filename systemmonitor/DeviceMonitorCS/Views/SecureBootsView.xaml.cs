using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Diagnostics;
using DeviceMonitorCS.Services;

namespace DeviceMonitorCS.Views
{
    public partial class SecureBootsView : UserControl
    {
        private readonly UefiService _uefiService;
        private List<DbxEntry> _allDbxEntries = new List<DbxEntry>();

        public SecureBootsView()
        {
            InitializeComponent();
            _uefiService = new UefiService();
            _uefiService.UefiChanged += (s, e) => 
            {
                Dispatcher.Invoke(async () => await InitializeAndLoad());
            };
        }

        public async Task InitializeAndLoad()
        {
            LoadingOverlay.Visibility = Visibility.Visible;
            
            try
            {
                await Task.Run(() =>
                {
                    // 1. Get DB Entries
                    var dbEntries = _uefiService.GetDbEntries();

                    // 2. Get DBX Entries
                    var dbxInfo = _uefiService.GetDbxInfo();
                    _allDbxEntries = dbxInfo.Entries;

                    // Update UI on UI Thread
                    Dispatcher.Invoke(() =>
                    {
                        DbGrid.ItemsSource = dbEntries;
                        DbCountText.Text = $"Allowed (db): {dbEntries.Count}";
                        
                        DbxCountText.Text = $"Revocations (dbx): {dbxInfo.Count}";


                        
                        // Show first 100 dbx entries initially to avoid lag if list is huge
                        DbxList.ItemsSource = _allDbxEntries.Take(100); 
                    });
                });
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() => MessageBox.Show($"Error reading UEFI variables: {ex.Message}"));
            }
            finally
            {
                LoadingOverlay.Visibility = Visibility.Collapsed;
            }
        }

        private void SearchBtn_Click(object sender, RoutedEventArgs e)
        {
            string query = SearchBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(query))
            {
                DbxList.ItemsSource = _allDbxEntries.Take(100);
            }
            else
            {
                // Simple containment search, case insensitive
                var results = _allDbxEntries
                    .Where(x => x.Hash.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0)
                    .Take(100) // Limit results for performance
                    .ToList();
                DbxList.ItemsSource = results;
            }
        }


    }
}
