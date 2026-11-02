using System;
using System.IO;

namespace DeviceMonitorCS.Services
{
    public class SettingsManager
    {
        private static SettingsManager _instance;
        public static SettingsManager Instance => _instance ?? (_instance = new SettingsManager());

        private bool _isFirstRun;
        public bool IsFirstRun
        {
            get => _isFirstRun;
            set
            {
                if (_isFirstRun != value)
                {
                    _isFirstRun = value;
                    SaveSettings();
                }
            }
        }

        private bool _isExpertMode;
        public bool IsExpertMode
        {
            get => _isExpertMode;
            set
            {
                if (_isExpertMode != value)
                {
                    _isExpertMode = value;
                    ExpertModeChanged?.Invoke(_isExpertMode);
                    SaveSettings();
                }
            }
        }

        private bool _isRemediationDebug;
        public bool IsRemediationDebug
        {
            get => _isRemediationDebug;
            set
            {
                if (_isRemediationDebug != value)
                {
                    _isRemediationDebug = value;
                    SaveSettings();
                }
            }
        }

        public event Action<bool> ExpertModeChanged;

        private SettingsManager()
        {
            LoadSettings();
        }

        private string GetSettingsPath()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DeviceMonitorCS", "general_settings.txt");
        }

        private void LoadSettings()
        {
            try
            {
                string path = GetSettingsPath();
                if (File.Exists(path))
                {
                    var lines = File.ReadAllLines(path);
                    if (lines.Length > 0) bool.TryParse(lines[0], out _isExpertMode);
                    if (lines.Length > 1) bool.TryParse(lines[1], out _isFirstRun);
                    else _isFirstRun = true;
                    if (lines.Length > 2) bool.TryParse(lines[2], out _isRemediationDebug);
                }
                else
                {
                    _isExpertMode = false;
                    _isFirstRun = true;
                    _isRemediationDebug = false;
                }
            }
            catch
            {
                _isExpertMode = false;
                _isFirstRun = true;
                _isRemediationDebug = false;
            }
        }

        private void SaveSettings()
        {
            try
            {
                string folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DeviceMonitorCS");
                Directory.CreateDirectory(folder);
                File.WriteAllLines(GetSettingsPath(), new[] { _isExpertMode.ToString(), _isFirstRun.ToString(), _isRemediationDebug.ToString() });
            }
            catch { }
        }
    }
}
