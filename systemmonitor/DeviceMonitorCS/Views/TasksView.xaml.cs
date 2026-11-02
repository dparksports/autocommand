using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using DeviceMonitorCS.Models;

namespace DeviceMonitorCS.Views
{
    public partial class TasksView : UserControl
    {
        public ObservableCollection<ScheduledTaskItem> RunningTasks { get; set; } = new ObservableCollection<ScheduledTaskItem>();
        public ObservableCollection<ScheduledTaskItem> ReadyTasks { get; set; } = new ObservableCollection<ScheduledTaskItem>();
        public ObservableCollection<ScheduledTaskItem> DisabledTasks { get; set; } = new ObservableCollection<ScheduledTaskItem>();

        public TasksView()
        {
            InitializeComponent();

            // TasksGrid.ItemsSource = TasksData; // Now bound in XAML via CollectionViewSource

            RefreshBtn.Click += (s, e) => LoadTasks();
            DisableBtn.Click += DisableBtn_Click;
            StopBtn.Click += StopBtn_Click;
            StartBtn.Click += StartBtn_Click;
            DeleteBtn.Click += DeleteBtn_Click;

            LoadTasks();

            this.Loaded += TasksView_Loaded;
        }

        private void TasksView_Loaded(object sender, RoutedEventArgs e)
        {
            // Initial load logic if needed
        }

        private void Grid_Loaded(object sender, RoutedEventArgs e)
        {
            if (sender is DataGrid grid)
            {
                UpdateGridLayout(grid);
            }
        }

        private void UpdateGridLayout(DataGrid grid)
        {
            if (grid == null) return;
            
            // Force re-layout to ensure headers are visible
            grid.UpdateLayout();
            
            // Toggle visibility to force refresh if needed
            if (grid.Columns.Count > 0)
            {
                var col = grid.Columns[0];
                var width = col.Width;
                col.Width = 0;
                col.Width = width;
            }
        }

        private async void LoadTasks()
        {
            try
            {
                // Clear existing items on UI thread
                RunningTasks.Clear();
                ReadyTasks.Clear();
                DisabledTasks.Clear();
                
                // Run the heavy 'schtasks.exe' query on a background thread
                var tasks = await System.Threading.Tasks.Task.Run(() => 
                {
                    var taskList = new System.Collections.Generic.List<ScheduledTaskItem>();
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        Arguments = "/query /FO CSV /V",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        StandardOutputEncoding = System.Text.Encoding.UTF8 
                    };

                    using (var process = Process.Start(startInfo))
                    {
                        string output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();

                        var lines = output.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                        
                        if (lines.Length > 1)
                        {
                            var headers = ParseCsvLine(lines[0]);
                            int idxTaskName = Array.IndexOf(headers, "TaskName");
                            int idxStatus = Array.IndexOf(headers, "Status");
                            int idxAction = Array.IndexOf(headers, "Task To Run");
                            int idxUser = Array.IndexOf(headers, "Run As User");

                            if (idxTaskName == -1) idxTaskName = 0; 

                            var addedTasks = new System.Collections.Generic.HashSet<string>();

                            for (int i = 1; i < lines.Length; i++)
                            {
                                var cols = ParseCsvLine(lines[i]);
                                if (cols.Length < 2) continue;

                                string taskName = GetCol(cols, idxTaskName);
                                
                                // Skip if this is a repeated header row
                                if (taskName == headers[idxTaskName]) continue;

                                // Skip if duplicate task (e.g. multiple triggers)
                                string tnClean = taskName.Trim('"');
                                if (addedTasks.Contains(tnClean)) continue;

                                addedTasks.Add(tnClean);
                               
                                // Split TaskPath and TaskName
                                string fullPath = tnClean;
                                string folder = "\\";
                                string name = fullPath;

                                int lastSlash = fullPath.LastIndexOf('\\');
                                if (lastSlash >= 0)
                                {
                                    if (lastSlash == 0)
                                    {
                                        folder = "\\"; 
                                        name = fullPath.Substring(1);
                                    }
                                    else
                                    {
                                        folder = fullPath.Substring(0, lastSlash);
                                        name = fullPath.Substring(lastSlash + 1);
                                    }
                                    
                                    // Simplify folder name
                                    if (folder.StartsWith(@"\Microsoft\Windows"))
                                    {
                                        folder = folder.Substring(@"\Microsoft\Windows".Length);
                                        if (folder.StartsWith("\\")) folder = folder.Substring(1);
                                        if (string.IsNullOrEmpty(folder)) folder = "Windows System"; 
                                    }
                                }
                               
                                taskList.Add(new ScheduledTaskItem
                                {
                                    TaskName = name,
                                    TaskPath = folder,
                                    State = GetCol(cols, idxStatus),
                                    Action = GetCol(cols, idxAction),
                                    User = GetCol(cols, idxUser)
                                });
                            }
                        }
                    }
                    return taskList;
                });

                // Update UI Collections on Main Thread
                foreach (var t in tasks)
                {
                    if (string.Equals(t.State, "Running", StringComparison.OrdinalIgnoreCase))
                    {
                        RunningTasks.Add(t);
                    }
                    else if (string.Equals(t.State, "Ready", StringComparison.OrdinalIgnoreCase))
                    {
                        ReadyTasks.Add(t);
                    }
                    else // Disabled or Unknown
                    {
                        DisabledTasks.Add(t);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to load tasks: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GetCol(string[] cols, int index)
        {
            if (index >= 0 && index < cols.Length) return cols[index];
            return "";
        }

        private string[] ParseCsvLine(string line)
        {
            return line.Split(new[] { "\",\"" }, StringSplitOptions.None)
                       .Select(s => s.Trim('"'))
                       .ToArray();
        }

        private void RunSchTasks(string args, string successMsg)
        {
            var selected = RunningGrid?.SelectedItem as ScheduledTaskItem 
                        ?? ReadyGrid?.SelectedItem as ScheduledTaskItem 
                        ?? DisabledGrid?.SelectedItem as ScheduledTaskItem;

            if (selected == null)
            {
                MessageBox.Show("Please select a task first.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                string fullTaskPath = selected.TaskPath.EndsWith("\\") 
                    ? selected.TaskPath + selected.TaskName 
                    : selected.TaskPath + "\\" + selected.TaskName;

                var startInfo = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = $"/TN \"{fullTaskPath}\" {args}",
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(startInfo))
                {
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    if (process.ExitCode == 0)
                    {
                        MessageBox.Show(successMsg, "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                        LoadTasks();
                    }
                    else
                    {
                        if (error.Contains("Access is denied"))
                        {
                            MessageBox.Show($"Access Denied: This task is protected by the system or requires additional permissions.\n\nTask: {selected.TaskName}", "Permission Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        }
                        else
                        {
                            MessageBox.Show($"Operation failed: {error}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DisableBtn_Click(object sender, RoutedEventArgs e)
        {
            RunSchTasks("/Change /DISABLE", $"Task disabled successfully.");
        }

        private void StopBtn_Click(object sender, RoutedEventArgs e)
        {
            RunSchTasks("/End", $"Task stopped successfully.");
        }

        private void StartBtn_Click(object sender, RoutedEventArgs e)
        {
            RunSchTasks("/Run", $"Task started successfully.");
        }

        private void DeleteBtn_Click(object sender, RoutedEventArgs e)
        {
             var selected = RunningGrid?.SelectedItem as ScheduledTaskItem 
                         ?? ReadyGrid?.SelectedItem as ScheduledTaskItem 
                         ?? DisabledGrid?.SelectedItem as ScheduledTaskItem;

            if (selected != null)
            {
                var res = MessageBox.Show($"Are you sure you want to delete task '{selected.TaskName}'?", "Confirm Delete", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (res == MessageBoxResult.Yes)
                {
                    RunSchTasks("/Delete /F", $"Task deleted successfully.");
                }
            }
        }

        private void AskAi_Click(object sender, RoutedEventArgs e)
        {
            var menuItem = sender as System.Windows.Controls.MenuItem;
            var contextMenu = menuItem.Parent as System.Windows.Controls.ContextMenu;
            var grid = contextMenu.PlacementTarget as System.Windows.Controls.DataGrid;

            if (grid != null && grid.SelectedItem != null)
            {
                var window = new AskAiWindow(grid.SelectedItem);
                window.Owner = Window.GetWindow(this);
                window.ShowDialog();
            }
        }
    }
}
